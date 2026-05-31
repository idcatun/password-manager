#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# SecureVault Password Manager
# GUI: GTK3 | Encryption: AES-256-CBC | Key Derivation: PBKDF2-HMAC-SHA256
# Auth: KEK architecture (vault key separate from master password derived key)
# =============================================================================

require 'gtk3'
require 'openssl'
require 'json'
require 'base64'
require 'securerandom'
require 'fileutils'

# =============================================================================
# Security Parameters
# =============================================================================
PBKDF2_ITERATIONS = 100_000
KEY_BYTES         = 32
SALT_BYTES        = 32
IV_BYTES          = 16
VAULT_DIR         = File.join(Dir.home, '.securevault')
VAULT_FILE        = File.join(VAULT_DIR, 'vault.dat')
META_FILE         = File.join(VAULT_DIR, 'vault.meta')
REMEMBER_FILE     = File.join(VAULT_DIR, 'remember')
THEME_FILE        = File.join(VAULT_DIR, 'theme')
APP_TITLE         = 'SecureVault'

MAX_LOGIN_ATTEMPTS = 5      # failed logins before each lockout
LOCKOUT_DURATIONS  = [      # escalating lockout durations in seconds
  60,        # 1st lockout  → 1 minute
  300,       # 2nd          → 5 minutes
  900,       # 3rd          → 15 minutes
  3_600,     # 4th          → 1 hour
  86_400,    # 5th          → 1 day
  604_800    # 6th+         → 1 week (max)
].freeze
LOCKOUT_FILE       = File.join(File.join(Dir.home, '.securevault'), 'lockout')
INACTIVITY_MINUTES = 5      # minutes of idle before auto-lock
CLIPBOARD_CLEAR_SECS = 30   # seconds before clipboard is wiped

# Fixed set of security questions (user answers first 3)
SECURITY_QUESTION_POOL = [
  'What was the name of your first pet?',
  'What city were you born in?',
  "What is your mother's maiden name?",
  'What was the name of your elementary school?',
  'What was your childhood nickname?',
  'What is the name of the street you grew up on?',
  'What was the make of your first car?',
  "What is your oldest sibling's middle name?",
  'What was the name of your childhood best friend?',
  'In what city did you meet your spouse or significant other?',
  'What was the name of the hospital where you were born?',
  'What is the middle name of your youngest child?'
].freeze

# =============================================================================
# Crypto – AES-256-CBC with PBKDF2-HMAC-SHA256 key derivation
# =============================================================================
module Crypto
  def self.derive_key(password, salt)
    OpenSSL::PKCS5.pbkdf2_hmac(
      password, salt, PBKDF2_ITERATIONS, KEY_BYTES, OpenSSL::Digest::SHA256.new
    )
  end

  # Encrypt a UTF-8 string → Base64 blob
  def self.encrypt(plaintext, key)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    iv         = cipher.random_iv
    cipher.key = key
    ct         = cipher.update(plaintext.encode('UTF-8')) + cipher.final
    Base64.strict_encode64(iv + ct)
  end

  # Decrypt a Base64 blob → UTF-8 string
  def self.decrypt(encoded, key)
    raw        = Base64.strict_decode64(encoded)
    iv         = raw[0, IV_BYTES]
    ct         = raw[IV_BYTES..]
    cipher     = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.decrypt
    cipher.key = key
    cipher.iv  = iv
    cipher.update(ct) + cipher.final
  rescue OpenSSL::Cipher::CipherError
    raise ArgumentError, 'Decryption failed – wrong password or corrupted data'
  end

  # Encrypt raw binary data (used for vault key wrapping) → Base64 blob
  def self.encrypt_raw(binary, key)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    iv         = cipher.random_iv
    cipher.key = key
    ct         = cipher.update(binary) + cipher.final
    Base64.strict_encode64(iv + ct)
  end

  # Decrypt Base64 blob → raw binary
  def self.decrypt_raw(encoded, key)
    raw        = Base64.strict_decode64(encoded)
    iv         = raw[0, IV_BYTES]
    ct         = raw[IV_BYTES..]
    cipher     = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.decrypt
    cipher.key = key
    cipher.iv  = iv
    (cipher.update(ct) + cipher.final).b
  rescue OpenSSL::Cipher::CipherError
    raise ArgumentError, 'Decryption failed'
  end

  # Constant-time comparison to prevent timing attacks
  def self.secure_compare(a, b)
    return false unless a.bytesize == b.bytesize
    OpenSSL.fixed_length_secure_compare(a, b)
  rescue StandardError
    a == b
  end
end

# =============================================================================
# Vault – KEK Architecture
#
# The vault key (vkey) is a random 32-byte value generated once at vault
# creation and never changes. It encrypts the credential data. Access to the
# vkey is controlled by two separate "envelopes":
#
#   master_blob  – vkey encrypted with a key derived from the master password
#   recovery_blob – vkey encrypted with a key derived from security Q&A answers
#
# Changing the master password only updates master_blob; the vkey and the
# encrypted data are untouched. Recovery works by decrypting recovery_blob.
# =============================================================================
class Vault
  attr_reader :entries, :username

  def initialize
    @entries  = []
    @vkey     = nil
    @username = nil
    FileUtils.mkdir_p(VAULT_DIR)
  end

  def exists? = File.exist?(VAULT_FILE) && File.exist?(META_FILE)
  def locked? = @vkey.nil?

  # Create a new vault.
  # sq_data: [{question: String, answer: String}, ...]
  # Each question gets its own recovery blob so any single answer can reset the password.
  def create!(username:, password:, sq_data:)
    vkey        = OpenSSL::Random.random_bytes(KEY_BYTES)
    master_salt = OpenSSL::Random.random_bytes(SALT_BYTES)
    master_key  = Crypto.derive_key(password, master_salt)
    master_blob = Crypto.encrypt_raw(vkey, master_key)

    questions = sq_data.map do |q|
      ans_norm = q[:answer].strip.downcase
      ans_salt = OpenSSL::Random.random_bytes(SALT_BYTES)
      ans_hash = Crypto.derive_key(ans_norm, ans_salt)
      rec_salt = OpenSSL::Random.random_bytes(SALT_BYTES)
      rec_key  = Crypto.derive_key(ans_norm, rec_salt)
      rec_blob = Crypto.encrypt_raw(vkey, rec_key)
      {
        'question'      => q[:question],
        'answer_hash'   => Base64.strict_encode64(ans_hash),
        'answer_salt'   => Base64.strict_encode64(ans_salt),
        'recovery_salt' => Base64.strict_encode64(rec_salt),
        'recovery_blob' => rec_blob
      }
    end

    meta = {
      'username'           => username,
      'master_salt'        => Base64.strict_encode64(master_salt),
      'master_blob'        => master_blob,
      'security_questions' => questions
    }
    File.write(META_FILE, JSON.generate(meta), encoding: 'UTF-8')

    @vkey     = vkey
    @username = username
    @entries  = []
    persist!
  end

  def unlock(username, password)
    return false unless exists?
    meta        = load_meta
    return false unless meta['username'] == username
    master_salt = Base64.strict_decode64(meta['master_salt'])
    master_key  = Crypto.derive_key(password, master_salt)
    vkey        = Crypto.decrypt_raw(meta['master_blob'], master_key)
    raw         = Crypto.decrypt(File.read(VAULT_FILE, encoding: 'UTF-8'), vkey)
    @entries    = JSON.parse(raw)
    @vkey       = vkey
    @username   = meta['username']
    true
  rescue ArgumentError, JSON::ParserError
    false
  end

  def lock!
    @entries  = []
    @vkey     = nil
    @username = nil
  end

  def security_questions
    return [] unless File.exist?(META_FILE)
    load_meta['security_questions'].map { |q| q['question'] }
  rescue StandardError
    []
  end

  # Verify a single answer by question index.
  def verify_single_answer(index, answer)
    return false unless File.exist?(META_FILE)
    sq = load_meta['security_questions'][index]
    return false unless sq
    ans_salt = Base64.strict_decode64(sq['answer_salt'])
    expected = Base64.strict_decode64(sq['answer_hash'])
    actual   = Crypto.derive_key(answer.strip.downcase, ans_salt)
    Crypto.secure_compare(expected, actual)
  rescue StandardError
    false
  end

  # Decrypt the recovery blob for the given question index and re-wrap the
  # vault key under a new master password.
  def reset_with_answer(index, answer, new_password)
    return false unless File.exist?(META_FILE)
    meta     = load_meta
    sq       = meta['security_questions'][index]
    return false unless sq
    rec_salt = Base64.strict_decode64(sq['recovery_salt'])
    rec_key  = Crypto.derive_key(answer.strip.downcase, rec_salt)
    vkey     = Crypto.decrypt_raw(sq['recovery_blob'], rec_key)

    new_salt = OpenSSL::Random.random_bytes(SALT_BYTES)
    new_key  = Crypto.derive_key(new_password, new_salt)
    new_blob = Crypto.encrypt_raw(vkey, new_key)

    meta['master_salt'] = Base64.strict_encode64(new_salt)
    meta['master_blob'] = new_blob
    File.write(META_FILE, JSON.generate(meta), encoding: 'UTF-8')
    true
  rescue ArgumentError
    false
  end

  def add_entry(name:, username:, password:, url: '', notes: '')
    @entries << {
      'id'         => SecureRandom.uuid,
      'name'       => name,
      'username'   => username,
      'password'   => password,
      'url'        => url,
      'notes'      => notes,
      'created_at' => Time.now.to_s,
      'updated_at' => Time.now.to_s
    }
    persist!
  end

  def update_entry(id, name:, username:, password:, url: '', notes: '')
    e = find(id)
    return false unless e
    e.merge!(
      'name' => name, 'username' => username, 'password' => password,
      'url'  => url,  'notes'    => notes,    'updated_at' => Time.now.to_s
    )
    persist!
    true
  end

  def delete_entry(id)
    @entries.reject! { |e| e['id'] == id }
    persist!
  end

  def find(id) = @entries.find { |e| e['id'] == id }

  def search(q)
    return @entries if q.nil? || q.strip.empty?
    lq = q.downcase
    @entries.select { |e|
      [e['name'], e['username'], e['url']].any? { |f| f.to_s.downcase.include?(lq) }
    }
  end

  private

  def load_meta
    JSON.parse(File.read(META_FILE, encoding: 'UTF-8'))
  end

  def persist!
    raise 'Vault is locked' if locked?
    File.write(VAULT_FILE, Crypto.encrypt(JSON.generate(@entries), @vkey), encoding: 'UTF-8')
  end
end

# =============================================================================
# Password Generator – cryptographically secure
# =============================================================================
module PasswordGen
  LOWER   = [*'a'..'z'].freeze
  UPPER   = [*'A'..'Z'].freeze
  DIGITS  = [*'0'..'9'].freeze
  SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?'.chars.freeze

  def self.generate(length: 16, upper: true, digits: true, symbols: true)
    pool     = LOWER.dup
    required = [rand_from(LOWER)]
    if upper;   pool += UPPER;   required << rand_from(UPPER);   end
    if digits;  pool += DIGITS;  required << rand_from(DIGITS);  end
    if symbols; pool += SYMBOLS; required << rand_from(SYMBOLS); end
    fill = Array.new([0, length - required.size].max) { rand_from(pool) }
    (required + fill).shuffle.join
  end

  def self.rand_from(arr)
    arr[SecureRandom.random_number(arr.size)]
  end
end

# =============================================================================
# Application Stylesheet
# =============================================================================
APP_CSS = <<~CSS
  .field-label {
    color: alpha(currentColor, 0.55);
    font-size: 0.82em;
    font-weight: bold;
    letter-spacing: 1px;
  }
  .empty-hint { color: alpha(currentColor, 0.4); }
  entry.monospace { font-family: monospace; }
CSS

# =============================================================================
# Utility helpers
# =============================================================================

def esc(str)
  str.to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;').gsub('"', '&quot;')
end

$sv_clip_source = nil

def clipboard_write(text)
  cb = Gtk::Clipboard.get(Gdk::Selection::CLIPBOARD)
  cb.text = text.to_s
  GLib::Source.remove($sv_clip_source) if $sv_clip_source
  $sv_clip_source = GLib::Timeout.add(CLIPBOARD_CLEAR_SECS * 1000) do
    cb.clear
    $sv_clip_source = nil
    false
  end
end

def status_flash(statusbar, ctx_id, msg, seconds: 4)
  statusbar.push(ctx_id, msg)
  GLib::Timeout.add(seconds * 1000) { statusbar.pop(ctx_id); false }
end

def format_duration(secs)
  case secs
  when 60      then '1 minute'
  when 300     then '5 minutes'
  when 900     then '15 minutes'
  when 3_600   then '1 hour'
  when 86_400  then '1 day'
  when 604_800 then '1 week'
  else              "#{secs} seconds"
  end
end

def format_remaining(secs)
  if    secs <= 60     then "#{secs} second#{secs == 1 ? '' : 's'}"
  elsif secs <= 3_600  then m = (secs / 60.0).ceil;  "#{m} minute#{m == 1 ? '' : 's'}"
  elsif secs <= 86_400 then h = (secs / 3_600.0).ceil; "#{h} hour#{h == 1 ? '' : 's'}"
  else                      d = (secs / 86_400.0).ceil; "#{d} day#{d == 1 ? '' : 's'}"
  end
end

def save_lockout_state(count, until_time)
  FileUtils.mkdir_p(File.dirname(LOCKOUT_FILE))
  data = { 'count' => count, 'until' => until_time&.iso8601 }
  File.write(LOCKOUT_FILE, JSON.generate(data), encoding: 'UTF-8')
rescue StandardError
end

def load_lockout_state
  data = JSON.parse(File.read(LOCKOUT_FILE, encoding: 'UTF-8'))
  until_time = data['until'] ? Time.parse(data['until']) : nil
  [data['count'].to_i, until_time]
rescue StandardError
  [0, nil]
end

def clear_lockout_state
  File.delete(LOCKOUT_FILE) if File.exist?(LOCKOUT_FILE)
rescue StandardError
end

def load_theme_preference
  File.read(THEME_FILE, encoding: 'UTF-8').strip == 'light' ? :light : :dark
rescue StandardError
  :dark
end

def save_theme_preference(mode)
  File.write(THEME_FILE, mode.to_s, encoding: 'UTF-8')
rescue StandardError
end

def remembered_username
  File.read(REMEMBER_FILE, encoding: 'UTF-8').strip
rescue StandardError
  nil
end

def save_remembered_username(username)
  File.write(REMEMBER_FILE, username, encoding: 'UTF-8')
rescue StandardError
end

def clear_remembered_username
  File.delete(REMEMBER_FILE) if File.exist?(REMEMBER_FILE)
rescue StandardError
end

def show_error_dialog(parent, message, secondary = nil)
  d = Gtk::MessageDialog.new(
    parent: parent, flags: :modal,
    type: :error, buttons_type: :ok,
    message: message
  )
  d.secondary_text = secondary if secondary
  d.run
  d.destroy
end

def show_confirm_dialog(parent, message, secondary = nil)
  d = Gtk::MessageDialog.new(
    parent: parent, flags: :modal,
    type: :warning, buttons_type: :yes_no,
    message: message
  )
  d.secondary_text = secondary if secondary
  d.default_response = Gtk::ResponseType::NO
  result = d.run == Gtk::ResponseType::YES
  d.destroy
  result
end

# =============================================================================
# Setup Dialog – shown once when creating a new vault
# Phase 1: username + password  →  Phase 2: security questions (dropdowns)
# =============================================================================
def open_setup_dialog
  d = Gtk::Dialog.new(title: 'Create New Vault', parent: nil, flags: [])
  d.set_default_size(520, -1)
  d.set_position(:center)
  d.deletable = false

  area = d.child
  area.margin = 20
  area.spacing = 8

  mk_row = lambda { |label_text, widget|
    row = Gtk::Box.new(:horizontal, 8)
    l = Gtk::Label.new(label_text)
    l.width_chars = 12
    l.xalign      = 1.0
    row.pack_start(l,      expand: false, fill: false, padding: 0)
    row.pack_start(widget, expand: true,  fill: true,  padding: 0)
    row
  }

  # ── Phase 1: Credentials ──────────────────────────────────────────────────
  phase1 = Gtk::Box.new(:vertical, 8)

  p1_title = Gtk::Label.new
  p1_title.markup = '<b><big>Create Your Vault</big></b>'
  p1_title.xalign = 0
  p1_sub = Gtk::Label.new
  p1_sub.markup = '<small>Choose a username and a strong master password.</small>'
  p1_sub.xalign = 0
  p1_sub.wrap   = true
  phase1.pack_start(p1_title, expand: false, fill: false, padding: 0)
  phase1.pack_start(p1_sub,   expand: false, fill: false, padding: 0)
  phase1.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 4)

  user_e = Gtk::Entry.new
  user_e.placeholder_text = 'Your vault username'
  user_e.hexpand          = true
  phase1.pack_start(mk_row.call('Username:', user_e), expand: false, fill: false, padding: 0)

  pass_e = Gtk::Entry.new
  pass_e.visibility       = false
  pass_e.placeholder_text = 'Master password (min 8 characters)'
  pass_e.hexpand          = true
  phase1.pack_start(mk_row.call('Password:', password_row_with_toggle(pass_e)), expand: false, fill: false, padding: 0)

  confirm_e = Gtk::Entry.new
  confirm_e.visibility       = false
  confirm_e.placeholder_text = 'Confirm password'
  confirm_e.hexpand          = true
  phase1.pack_start(mk_row.call('Confirm:', password_row_with_toggle(confirm_e)), expand: false, fill: false, padding: 0)

  build_strength_indicator(phase1, pass_e)

  err1 = Gtk::Label.new
  err1.xalign = 0
  phase1.pack_start(err1, expand: false, fill: false, padding: 0)

  continue_btn = Gtk::Button.new(label: 'Continue →')
  continue_btn.style_context.add_class('suggested-action')
  phase1.pack_start(continue_btn, expand: false, fill: false, padding: 0)

  area.pack_start(phase1, expand: false, fill: false, padding: 0)

  # ── Phase 2: Security Questions ───────────────────────────────────────────
  phase2 = Gtk::Box.new(:vertical, 8)

  p2_title = Gtk::Label.new
  p2_title.markup = '<b><big>Security Questions</big></b>'
  p2_title.xalign = 0
  p2_sub = Gtk::Label.new
  p2_sub.markup = '<small>Select 3 questions and provide your answers. These will be used to reset your password if forgotten.</small>'
  p2_sub.xalign = 0
  p2_sub.wrap   = true
  phase2.pack_start(p2_title, expand: false, fill: false, padding: 0)
  phase2.pack_start(p2_sub,   expand: false, fill: false, padding: 0)
  phase2.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 4)

  placeholder_q = '— select a question —'.freeze

  # Build 3 question rows: [ComboBoxText, Entry]
  sq_rows = 3.times.map do
    cb = Gtk::ComboBoxText.new
    cb.append_text(placeholder_q)
    SECURITY_QUESTION_POOL.each { |q| cb.append_text(q) }
    cb.active = 0
    cb.hexpand = true

    ans_e = Gtk::Entry.new
    ans_e.placeholder_text = 'Your answer'
    ans_e.hexpand          = true

    row = Gtk::Box.new(:vertical, 4)
    row.pack_start(cb,    expand: false, fill: false, padding: 0)
    row.pack_start(ans_e, expand: false, fill: false, padding: 0)
    phase2.pack_start(row, expand: false, fill: false, padding: 0)

    [cb, ans_e]
  end

  err2 = Gtk::Label.new
  err2.xalign = 0
  phase2.pack_start(err2, expand: false, fill: false, padding: 0)

  area.pack_start(phase2, expand: false, fill: false, padding: 0)

  # ── Dialog buttons ────────────────────────────────────────────────────────
  d.add_button('Quit', Gtk::ResponseType::CANCEL)
  ok_btn = d.add_button('Create Vault', Gtk::ResponseType::OK)
  ok_btn.style_context.add_class('suggested-action')
  ok_btn.sensitive = false
  d.default_response = Gtk::ResponseType::OK

  d.show_all
  phase2.hide

  # Stored credentials from phase 1
  saved_username = nil
  saved_password = nil

  # Continue button validates phase 1 and transitions to phase 2
  continue_btn.signal_connect('clicked') do
    un = user_e.text.strip
    pw = pass_e.text

    if un.empty?
      err1.markup = "<span foreground='red'>⚠ Username is required</span>"
    elsif pw.empty?
      err1.markup = "<span foreground='red'>⚠ Password is required</span>"
    elsif pw.length < 8
      err1.markup = "<span foreground='red'>⚠ Password must be at least 8 characters</span>"
    elsif pw != confirm_e.text
      err1.markup = "<span foreground='red'>⚠ Passwords do not match</span>"
    else
      saved_username = un
      saved_password = pw
      pos = d.position
      phase1.hide
      phase2.show
      d.resize(520, 1)
      d.move(*pos)
      ok_btn.sensitive = true
    end
  end

  loop do
    resp = d.run
    unless resp == Gtk::ResponseType::OK
      d.destroy
      return nil
    end

    # Validate phase 2
    selected_questions = sq_rows.map { |cb, _| cb.active_text }
    answers            = sq_rows.map { |_, e| e.text.strip }

    if selected_questions.any? { |q| q.nil? || q == placeholder_q }
      err2.markup = "<span foreground='red'>⚠ Please select a question for each row</span>"
      next
    end
    if selected_questions.uniq.length < selected_questions.length
      err2.markup = "<span foreground='red'>⚠ Please choose a different question for each row</span>"
      next
    end
    if answers.any?(&:empty?)
      err2.markup = "<span foreground='red'>⚠ Please answer all security questions</span>"
      next
    end

    d.destroy
    sq_data = selected_questions.zip(answers).map { |q, a| { question: q, answer: a } }
    return { username: saved_username, password: saved_password, sq_data: sq_data }
  end
end

# =============================================================================
# Master Password / Unlock Dialog
# Returns: {username:, password:, remember:} on success, :forgot, or nil on quit
# =============================================================================
def open_master_dialog(error_msg: nil)
  remembered = remembered_username

  d = Gtk::Dialog.new(title: "Unlock #{APP_TITLE}", parent: nil, flags: [])
  d.set_default_size(430, -1)
  d.set_position(:center)
  d.deletable = false

  area = d.child
  area.margin = 20
  area.spacing = 10

  top  = Gtk::Box.new(:horizontal, 14)
  icon = Gtk::Image.new(icon_name: 'system-lock-screen', icon_size: :dialog)
  top.pack_start(icon, expand: false, fill: false, padding: 0)

  hbox    = Gtk::Box.new(:vertical, 4)
  title_l = Gtk::Label.new
  title_l.markup = remembered ?
    "<b><big>Welcome back, #{esc remembered}!</big></b>" :
    '<b><big>Unlock Your Vault</big></b>'
  title_l.xalign = 0

  sub_l = Gtk::Label.new
  sub_l.markup = '<small>Enter your username and master password to continue.</small>'
  sub_l.xalign = 0
  sub_l.wrap   = true

  hbox.pack_start(title_l, expand: false)
  hbox.pack_start(sub_l,   expand: false)
  top.pack_start(hbox, expand: true, fill: true, padding: 0)
  area.pack_start(top,                             expand: false, fill: false, padding: 0)
  area.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 0)

  mk_row = lambda { |label_text, entry_widget|
    row = Gtk::Box.new(:horizontal, 8)
    l = Gtk::Label.new(label_text)
    l.width_chars = 10
    l.xalign      = 1.0
    row.pack_start(l,            expand: false, fill: false, padding: 0)
    row.pack_start(entry_widget, expand: true,  fill: true,  padding: 0)
    row
  }

  user_e = Gtk::Entry.new
  user_e.placeholder_text  = 'Username'
  user_e.hexpand           = true
  user_e.text              = remembered || ''
  area.pack_start(mk_row.call('Username:', user_e), expand: false, fill: false, padding: 0)

  pass_e = Gtk::Entry.new
  pass_e.visibility        = false
  pass_e.placeholder_text  = 'Master password'
  pass_e.activates_default = true
  pass_e.hexpand           = true
  area.pack_start(mk_row.call('Password:', password_row_with_toggle(pass_e)), expand: false, fill: false, padding: 0)

  remember_cb = Gtk::CheckButton.new('Remember me')
  remember_cb.active = !remembered.nil?
  area.pack_start(remember_cb, expand: false, fill: false, padding: 0)

  err_lbl = Gtk::Label.new
  err_lbl.xalign = 0
  err_lbl.markup = "<span foreground='red'>#{esc error_msg}</span>" if error_msg
  area.pack_start(err_lbl, expand: false, fill: false, padding: 0)

  forgot_btn = Gtk::Button.new(label: 'Forgot password?')
  forgot_btn.relief = :none
  forgot_btn.signal_connect('clicked') { d.response(Gtk::ResponseType::HELP) }
  area.pack_start(forgot_btn, expand: false, fill: false, padding: 0)

  d.add_button('Quit', Gtk::ResponseType::CANCEL)
  ok_btn = d.add_button('Unlock', Gtk::ResponseType::OK)
  ok_btn.style_context.add_class('suggested-action')
  d.default_response = Gtk::ResponseType::OK

  # If username is pre-filled, jump focus to password
  pass_e.grab_focus if remembered

  d.show_all

  loop do
    resp = d.run
    case resp
    when Gtk::ResponseType::OK
      un = user_e.text.strip
      pw = pass_e.text
      if un.empty?
        err_lbl.markup = "<span foreground='red'>⚠ Username cannot be empty</span>"
        next
      end
      if pw.empty?
        err_lbl.markup = "<span foreground='red'>⚠ Password cannot be empty</span>"
        next
      end
      remember = remember_cb.active?
      d.destroy
      return { username: un, password: pw, remember: remember }
    when Gtk::ResponseType::HELP
      d.destroy
      return :forgot
    else
      d.destroy
      return nil
    end
  end
end

# =============================================================================
# Forgot Password Dialog
# Phase 1: pick one security question + answer  →  Phase 2: set new password
# Returns true if password was successfully reset.
# =============================================================================
def open_forgot_dialog(vault)
  questions = vault.security_questions
  if questions.empty?
    show_error_dialog(nil, 'No security questions found.',
      'This vault was created without security questions and cannot be recovered.')
    return false
  end

  d = Gtk::Dialog.new(title: 'Reset Master Password', parent: nil, flags: [])
  d.set_default_size(480, -1)
  d.set_position(:center)
  d.deletable = false

  area = d.child
  area.margin = 20
  area.spacing = 8

  # ── Phase 1: Pick question + answer ──────────────────────────────────────
  phase1 = Gtk::Box.new(:vertical, 8)

  p1_title = Gtk::Label.new
  p1_title.markup = '<b><big>Reset Master Password</big></b>'
  p1_title.xalign = 0
  p1_sub = Gtk::Label.new
  p1_sub.markup = '<small>Select one of your security questions and enter the answer.</small>'
  p1_sub.xalign = 0
  p1_sub.wrap   = true
  phase1.pack_start(p1_title, expand: false, fill: false, padding: 0)
  phase1.pack_start(p1_sub,   expand: false, fill: false, padding: 0)
  phase1.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 4)

  q_cb = Gtk::ComboBoxText.new
  questions.each { |q| q_cb.append_text(q) }
  q_cb.active  = 0
  q_cb.hexpand = true
  phase1.pack_start(q_cb, expand: false, fill: false, padding: 0)

  ans_e = Gtk::Entry.new
  ans_e.placeholder_text = 'Your answer'
  ans_e.hexpand          = true
  phase1.pack_start(ans_e, expand: false, fill: false, padding: 0)

  err1 = Gtk::Label.new
  err1.xalign = 0
  phase1.pack_start(err1, expand: false, fill: false, padding: 0)

  verify_btn = Gtk::Button.new(label: 'Verify Answer →')
  verify_btn.style_context.add_class('suggested-action')
  phase1.pack_start(verify_btn, expand: false, fill: false, padding: 0)

  area.pack_start(phase1, expand: false, fill: false, padding: 0)

  # ── Phase 2: New Password ─────────────────────────────────────────────────
  phase2 = Gtk::Box.new(:vertical, 8)

  p2_title = Gtk::Label.new
  p2_title.markup = '<b><big>Set New Master Password</big></b>'
  p2_title.xalign = 0
  phase2.pack_start(p2_title, expand: false, fill: false, padding: 0)

  mk_row = lambda { |label_text, entry_widget|
    row = Gtk::Box.new(:horizontal, 8)
    l = Gtk::Label.new(label_text)
    l.width_chars = 10
    l.xalign      = 1.0
    row.pack_start(l,            expand: false, fill: false, padding: 0)
    row.pack_start(entry_widget, expand: true,  fill: true,  padding: 0)
    row
  }

  new_pass_e = Gtk::Entry.new
  new_pass_e.visibility       = false
  new_pass_e.placeholder_text = 'New master password (min 8 characters)'
  new_pass_e.hexpand          = true
  phase2.pack_start(mk_row.call('Password:', password_row_with_toggle(new_pass_e)), expand: false, fill: false, padding: 0)

  build_strength_indicator(phase2, new_pass_e)

  new_confirm_e = Gtk::Entry.new
  new_confirm_e.visibility       = false
  new_confirm_e.placeholder_text = 'Confirm new password'
  new_confirm_e.hexpand          = true
  phase2.pack_start(mk_row.call('Confirm:', password_row_with_toggle(new_confirm_e)), expand: false, fill: false, padding: 0)

  err2 = Gtk::Label.new
  err2.xalign = 0
  phase2.pack_start(err2, expand: false, fill: false, padding: 0)

  area.pack_start(phase2, expand: false, fill: false, padding: 0)

  # ── Buttons ───────────────────────────────────────────────────────────────
  d.add_button('Cancel', Gtk::ResponseType::CANCEL)
  reset_btn = d.add_button('Reset Password', Gtk::ResponseType::OK)
  reset_btn.sensitive = false

  d.show_all
  phase2.hide

  verified_index  = nil
  verified_answer = nil

  verify_btn.signal_connect('clicked') do
    idx = q_cb.active
    ans = ans_e.text
    if ans.strip.empty?
      err1.markup = "<span foreground='red'>⚠ Please enter your answer</span>"
    elsif vault.verify_single_answer(idx, ans)
      verified_index  = idx
      verified_answer = ans
      pos = d.position
      phase1.hide
      phase2.show
      d.resize(480, 1)
      d.move(*pos)
      reset_btn.sensitive = true
      new_pass_e.grab_focus
    else
      err1.markup = "<span foreground='red'>⚠ Incorrect answer – please try again</span>"
    end
  end

  result = false
  loop do
    resp = d.run
    unless resp == Gtk::ResponseType::OK
      break
    end

    np = new_pass_e.text
    if np.empty?
      err2.markup = "<span foreground='red'>⚠ Password cannot be empty</span>"
      next
    end
    if np.length < 8
      err2.markup = "<span foreground='red'>⚠ Minimum 8 characters required</span>"
      next
    end
    if np != new_confirm_e.text
      err2.markup = "<span foreground='red'>⚠ Passwords do not match</span>"
      next
    end
    if vault.reset_with_answer(verified_index, verified_answer, np)
      result = true
      break
    else
      err2.markup = "<span foreground='red'>⚠ Reset failed – please try again</span>"
    end
  end

  d.destroy
  result
end

# Adds a live password strength indicator to +container+ tracking +pass_e+.
# Initializes immediately so GTK allocates layout space before the user types.
# Returns the update lambda so callers can retrigger it (e.g. after Generate).
def build_strength_indicator(container, pass_e)
  s_lbl = Gtk::Label.new
  s_lbl.xalign = 0
  r_lbl = Gtk::Label.new
  r_lbl.xalign = 0
  r_lbl.wrap   = true

  box = Gtk::Box.new(:vertical, 2)
  box.pack_start(s_lbl, expand: false, fill: false, padding: 0)
  box.pack_start(r_lbl, expand: false, fill: false, padding: 0)
  container.pack_start(box, expand: false, fill: false, padding: 0)

  update = lambda do
    pw   = pass_e.text
    reqs = {
      length: pw.length >= 8,
      upper:  pw.match?(/[A-Z]/),
      lower:  pw.match?(/[a-z]/),
      digit:  pw.match?(/[0-9]/),
      symbol: pw.match?(/[^A-Za-z0-9]/)
    }
    met = reqs.values.count(true)
    if pw.empty?
      s_lbl.markup = "<small><b><span foreground='#999999'>No password entered</span></b></small>"
    else
      st_label, st_color = case met
        when 0..1 then ['Very Weak',   '#e53935']
        when 2    then ['Weak',        '#f57c00']
        when 3    then ['Moderate',    '#f9a825']
        when 4    then ['Strong',      '#7cb342']
        else           ['Very Strong', '#2e7d32']
      end
      s_lbl.markup = "<small><b><span foreground='#{st_color}'>#{st_label}</span></b></small>"
    end
    parts = [
      [reqs[:length], '8+ chars'],
      [reqs[:upper],  'Uppercase'],
      [reqs[:lower],  'Lowercase'],
      [reqs[:digit],  'Number'],
      [reqs[:symbol], 'Symbol']
    ].map { |met, label|
      color = met ? '#7cb342' : '#e53935'
      mark  = met ? '✓' : '✗'
      "<span foreground='#{color}'>#{mark} #{esc label}</span>"
    }.join('   ')
    r_lbl.markup = "<small>#{parts}</small>"
  end

  pass_e.signal_connect('changed') { update.call }
  update.call  # run once immediately so GTK allocates label space from the start
  update       # return lambda
end

# Wraps a password entry with a show/hide toggle button.
def password_row_with_toggle(pass_e)
  btn = Gtk::ToggleButton.new
  btn.image        = Gtk::Image.new(icon_name: 'view-reveal-symbolic', icon_size: :button)
  btn.tooltip_text = 'Show / hide password'
  btn.relief       = :none
  btn.signal_connect('toggled') { |b| pass_e.visibility = b.active? }
  box = Gtk::Box.new(:horizontal, 4)
  box.pack_start(pass_e, expand: true,  fill: true,  padding: 0)
  box.pack_start(btn,    expand: false, fill: false, padding: 0)
  box.hexpand = true
  box
end


def open_entry_dialog(parent, entry = nil)
  editing = !entry.nil?
  d = Gtk::Dialog.new(
    title:  editing ? 'Edit Credential' : 'Add Credential',
    parent: parent,
    flags:  [:modal, :destroy_with_parent]
  )
  d.set_default_size(490, 415)

  area = d.child
  area.margin = 16
  area.spacing = 10

  grid = Gtk::Grid.new
  grid.column_spacing = 10
  grid.row_spacing    = 8

  mk_entry = lambda { |ph|
    e = Gtk::Entry.new
    e.placeholder_text = ph
    e.hexpand = true
    e
  }

  name_e = mk_entry.call('e.g. Gmail, GitHub, Netflix')
  user_e = mk_entry.call('username or email')
  url_e  = mk_entry.call('https://example.com')
  pass_e = mk_entry.call('password')
  pass_e.visibility = false

  # Password row with show-toggle and generator button
  show_btn = Gtk::ToggleButton.new
  show_btn.image        = Gtk::Image.new(icon_name: 'view-reveal-symbolic', icon_size: :button)
  show_btn.tooltip_text = 'Show / Hide password'
  show_btn.signal_connect('toggled') { |b| pass_e.visibility = b.active? }

  gen_btn = Gtk::Button.new(label: 'Generate')
  gen_btn.tooltip_text = 'Generate a random password'
  gen_btn.signal_connect('clicked') do
    pass_e.text       = PasswordGen.generate
    pass_e.visibility = true
    show_btn.active   = true
  end

  pass_row = Gtk::Box.new(:horizontal, 4)
  pass_row.pack_start(pass_e,   expand: true,  fill: true,  padding: 0)
  pass_row.pack_start(show_btn, expand: false, fill: false, padding: 0)
  pass_row.pack_start(gen_btn,  expand: false, fill: false, padding: 0)
  pass_row.hexpand = true

  rows = [
    ['Name *',     name_e],
    ['Username *', user_e],
    ['Password *', pass_row],
    ['URL',        url_e]
  ]
  rows.each_with_index do |(label, widget), i|
    lbl = Gtk::Label.new(label)
    lbl.xalign = 1.0
    lbl.style_context.add_class('field-label')
    grid.attach(lbl,    0, i, 1, 1)
    grid.attach(widget, 1, i, 1, 1)
  end

  area.pack_start(grid, expand: false, fill: false, padding: 0)

  strength_update = build_strength_indicator(area, pass_e)
  gen_btn.signal_connect('clicked') { strength_update.call }

  notes_lbl = Gtk::Label.new('Notes')
  notes_lbl.xalign = 0
  area.pack_start(notes_lbl, expand: false, fill: false, padding: 0)

  notes_buf  = Gtk::TextBuffer.new
  notes_view = Gtk::TextView.new(notes_buf)
  notes_view.wrap_mode = :word_char
  notes_sw = Gtk::ScrolledWindow.new
  notes_sw.set_policy(:automatic, :automatic)
  notes_sw.set_size_request(-1, 90)
  notes_sw.add(notes_view)
  notes_sw.vexpand = true
  area.pack_start(notes_sw, expand: true, fill: true, padding: 0)

  err_lbl = Gtk::Label.new
  err_lbl.xalign = 0
  area.pack_start(err_lbl, expand: false, fill: false, padding: 0)

  if editing
    name_e.text    = entry['name']     || ''
    user_e.text    = entry['username'] || ''
    pass_e.text    = entry['password'] || ''
    url_e.text     = entry['url']      || ''
    notes_buf.text = entry['notes']    || ''
  end

  d.add_button('Cancel', Gtk::ResponseType::CANCEL)
  ok_btn = d.add_button(editing ? 'Save Changes' : 'Add Credential', Gtk::ResponseType::OK)
  ok_btn.style_context.add_class('suggested-action')
  d.default_response = Gtk::ResponseType::OK
  d.show_all

  loop do
    resp = d.run
    unless resp == Gtk::ResponseType::OK
      d.destroy
      return nil
    end

    nm = name_e.text.strip
    us = user_e.text.strip
    pw = pass_e.text
    ur = url_e.text.strip
    no = notes_buf.text.strip

    if nm.empty?
      err_lbl.markup = "<span foreground='red'>⚠ Name is required</span>"
      next
    end
    if us.empty?
      err_lbl.markup = "<span foreground='red'>⚠ Username is required</span>"
      next
    end
    if pw.empty?
      err_lbl.markup = "<span foreground='red'>⚠ Password is required</span>"
      next
    end

    d.destroy
    return { name: nm, username: us, password: pw, url: ur, notes: no }
  end
end

# =============================================================================
# Detail Panel – right-side credential view
# =============================================================================
def build_detail_panel(entry, on_edit:, on_delete:, on_copy:)
  box = Gtk::Box.new(:vertical, 0)
  box.margin = 20

  # Title row
  title_row = Gtk::Box.new(:horizontal, 8)
  name_lbl  = Gtk::Label.new
  name_lbl.markup = "<b><big>#{esc entry['name']}</big></b>"
  name_lbl.xalign = 0
  name_lbl.hexpand = true
  title_row.pack_start(name_lbl, expand: true, fill: true, padding: 0)

  edit_btn = Gtk::Button.new
  edit_btn.image        = Gtk::Image.new(icon_name: 'document-edit-symbolic', icon_size: :button)
  edit_btn.tooltip_text = 'Edit'
  edit_btn.relief       = :none
  edit_btn.signal_connect('clicked') { on_edit.call }

  del_btn = Gtk::Button.new
  del_btn.image        = Gtk::Image.new(icon_name: 'user-trash-symbolic', icon_size: :button)
  del_btn.tooltip_text = 'Delete'
  del_btn.relief       = :none
  del_btn.signal_connect('clicked') { on_delete.call }

  title_row.pack_start(edit_btn, expand: false, fill: false, padding: 0)
  title_row.pack_start(del_btn,  expand: false, fill: false, padding: 0)
  box.pack_start(title_row, expand: false, fill: false, padding: 0)
  box.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 8)

  mk_field = lambda { |label, value, copyable: true|
    row = Gtk::Box.new(:vertical, 2)
    lbl = Gtk::Label.new(label.upcase)
    lbl.xalign = 0
    lbl.style_context.add_class('field-label')
    row.pack_start(lbl, expand: false)

    inner = Gtk::Box.new(:horizontal, 4)
    val_lbl = Gtk::Label.new(value.to_s)
    val_lbl.xalign      = 0
    val_lbl.selectable  = true
    val_lbl.wrap        = true
    val_lbl.hexpand     = true
    inner.pack_start(val_lbl, expand: true, fill: true, padding: 0)

    if copyable && !value.to_s.empty?
      copy_btn = Gtk::Button.new
      copy_btn.image        = Gtk::Image.new(icon_name: 'edit-copy-symbolic', icon_size: :button)
      copy_btn.tooltip_text = "Copy #{label}"
      copy_btn.relief       = :none
      copy_btn.signal_connect('clicked') { on_copy.call(value, label) }
      inner.pack_start(copy_btn, expand: false, fill: false, padding: 0)
    end

    row.pack_start(inner, expand: false)
    box.pack_start(row, expand: false, fill: false, padding: 0)
    box.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 4)
  }

  mk_field.call('Username', entry['username'])
  mk_field.call('URL',      entry['url'])

  # Password field with show/hide toggle
  pw_row  = Gtk::Box.new(:vertical, 2)
  pw_lbl  = Gtk::Label.new('PASSWORD')
  pw_lbl.xalign = 0
  pw_lbl.style_context.add_class('field-label')
  pw_row.pack_start(pw_lbl, expand: false)

  pw_inner = Gtk::Box.new(:horizontal, 4)
  pw_val   = Gtk::Label.new('••••••••••••')
  pw_val.xalign   = 0
  pw_val.hexpand  = true
  pw_inner.pack_start(pw_val, expand: true, fill: true, padding: 0)

  show_btn = Gtk::ToggleButton.new
  show_btn.image        = Gtk::Image.new(icon_name: 'view-reveal-symbolic', icon_size: :button)
  show_btn.tooltip_text = 'Show / Hide password'
  show_btn.relief       = :none
  show_btn.signal_connect('toggled') do |b|
    pw_val.text = b.active? ? entry['password'].to_s : '••••••••••••'
  end

  copy_btn = Gtk::Button.new
  copy_btn.image        = Gtk::Image.new(icon_name: 'edit-copy-symbolic', icon_size: :button)
  copy_btn.tooltip_text = 'Copy Password'
  copy_btn.relief       = :none
  copy_btn.signal_connect('clicked') { on_copy.call(entry['password'], 'Password') }

  pw_inner.pack_start(show_btn, expand: false, fill: false, padding: 0)
  pw_inner.pack_start(copy_btn, expand: false, fill: false, padding: 0)
  pw_row.pack_start(pw_inner, expand: false)
  box.pack_start(pw_row,                      expand: false, fill: false, padding: 0)
  box.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 4)

  unless entry['notes'].to_s.empty?
    mk_field.call('Notes', entry['notes'], copyable: false)
  end

  ts = entry['updated_at'] || entry['created_at']
  if ts
    ts_lbl = Gtk::Label.new("Last updated: #{ts}")
    ts_lbl.xalign = 0
    ts_lbl.style_context.add_class('field-label')
    box.pack_start(ts_lbl, expand: false, fill: false, padding: 0)
  end

  box.show_all
  box
end

def build_empty_detail
  box = Gtk::Box.new(:vertical, 12)
  box.valign = :center
  box.hexpand = true
  box.vexpand = true

  img = Gtk::Image.new(icon_name: 'system-lock-screen', icon_size: :dialog)
  lbl = Gtk::Label.new
  lbl.markup = '<span alpha="40%">Select an entry to view its details</span>'
  lbl.style_context.add_class('empty-hint')

  box.pack_start(img, expand: false)
  box.pack_start(lbl, expand: false)
  box
end

# =============================================================================
# Main Application
# =============================================================================
class App
  def initialize
    @vault            = Vault.new
    @selected_id      = nil
    @search_query     = ''
    @current_theme    = load_theme_preference
    @login_attempts   = 0
    @lockout_count, @locked_until = load_lockout_state
    @inactivity_timer = nil
    apply_css
    build_window
    apply_theme(@current_theme)
    GLib::Idle.add { show_auth_screen; false }
  end

  def run
    Gtk.main
  end

  private

  def apply_theme(mode)
    @current_theme = mode
    dark = (mode == :dark)
    Gtk::Settings.default.gtk_application_prefer_dark_theme = dark
    if @theme_btn
      @theme_btn.label        = dark ? '☀' : '🌙'
      @theme_btn.tooltip_text = dark ? 'Switch to light mode' : 'Switch to dark mode'
    end
    save_theme_preference(mode)
  end

  def reset_inactivity_timer
    GLib::Source.remove(@inactivity_timer) if @inactivity_timer
    @inactivity_timer = GLib::Timeout.add(INACTIVITY_MINUTES * 60 * 1000) do
      unless @vault.locked?
        do_lock
      end
      @inactivity_timer = nil
      false
    end
  end

  def toggle_theme
    apply_theme(@current_theme == :dark ? :light : :dark)
  end

  def apply_css
    prov = Gtk::CssProvider.new
    prov.load_from_data(APP_CSS)
    Gtk::StyleContext.add_provider_for_screen(
      Gdk::Screen.default, prov,
      Gtk::StyleProvider::PRIORITY_APPLICATION
    )
  end

  def build_window
    @win = Gtk::Window.new
    @win.title = APP_TITLE
    @win.set_default_size(840, 580)
    @win.set_position(:center)
    @win.signal_connect('delete-event') { Gtk.main_quit; false }

    @hbar = Gtk::HeaderBar.new
    @hbar.title             = APP_TITLE
    @hbar.subtitle          = 'Password Manager'
    @hbar.show_close_button = true
    @win.set_titlebar(@hbar)

    @add_btn = Gtk::Button.new
    @add_btn.image        = Gtk::Image.new(icon_name: 'list-add-symbolic', icon_size: :button)
    @add_btn.tooltip_text = 'Add credential  (Ctrl+N)'
    @add_btn.signal_connect('clicked') { do_add }
    @hbar.pack_start(@add_btn)

    lock_btn = Gtk::Button.new
    lock_btn.image        = Gtk::Image.new(icon_name: 'changes-prevent-symbolic', icon_size: :button)
    lock_btn.tooltip_text = 'Lock vault  (Ctrl+L)'
    lock_btn.signal_connect('clicked') { do_lock }
    @hbar.pack_end(lock_btn)

    @theme_btn = Gtk::Button.new(label: '🌙')
    @theme_btn.tooltip_text = 'Switch to light mode'
    @theme_btn.signal_connect('clicked') { toggle_theme }
    @hbar.pack_end(@theme_btn)

    @count_lbl = Gtk::Label.new('0 entries')
    @hbar.pack_end(@count_lbl)

    root = Gtk::Box.new(:vertical, 0)

    sbar = Gtk::Box.new(:horizontal, 8)
    sbar.margin = 8
    @search_e = Gtk::SearchEntry.new
    @search_e.placeholder_text = 'Search by name, username or URL…'
    @search_e.hexpand = true
    @search_e.signal_connect('search-changed') { |e| do_search(e.text) }
    sbar.pack_start(@search_e, expand: true, fill: true, padding: 0)
    root.pack_start(sbar, expand: false, fill: false, padding: 0)
    root.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 0)

    @paned          = Gtk::Paned.new(:horizontal)
    @paned.position = 268
    @paned.vexpand  = true
    @paned.pack1(build_list_panel, resize: false, shrink: false)

    @detail_sw = Gtk::ScrolledWindow.new
    @detail_sw.set_policy(:never, :automatic)
    @detail_sw.hexpand = true
    @detail_sw.vexpand = true
    swap_detail(build_empty_detail)
    @paned.pack2(@detail_sw, resize: true, shrink: false)

    root.pack_start(@paned, expand: true, fill: true, padding: 0)

    @statusbar = Gtk::Statusbar.new
    @sb_ctx    = @statusbar.get_context_id('app')
    root.pack_start(@statusbar, expand: false, fill: false, padding: 0)

    @win.add(root)

    @win.signal_connect('key-press-event') do |_, ev|
      reset_inactivity_timer
      if ev.state.control_mask?
        case ev.keyval
        when Gdk::Keyval::KEY_n then do_add
        when Gdk::Keyval::KEY_l then do_lock
        when Gdk::Keyval::KEY_f then @search_e.grab_focus
        end
      end
    end

    @win.signal_connect('button-press-event') { reset_inactivity_timer }
  end

  def build_list_panel
    left = Gtk::Box.new(:vertical, 0)
    left.set_size_request(245, -1)

    sw = Gtk::ScrolledWindow.new
    sw.set_policy(:never, :automatic)
    sw.vexpand = true

    @store = Gtk::ListStore.new(String, String, String)

    @tree = Gtk::TreeView.new(@store)
    @tree.headers_visible         = false
    @tree.activate_on_single_click = false

    col    = Gtk::TreeViewColumn.new
    icon_r = Gtk::CellRendererPixbuf.new
    icon_r.icon_name  = 'dialog-password'
    icon_r.stock_size = 4
    col.pack_start(icon_r, false)

    text_r = Gtk::CellRendererText.new
    text_r.ellipsize = :end
    col.pack_start(text_r, true)
    col.set_cell_data_func(text_r) do |_c, r, _m, iter|
      r.markup = "<b>#{esc iter[1]}</b>\n<small>#{esc iter[2]}</small>"
    end

    @tree.append_column(col)

    @tree.signal_connect('cursor-changed') do
      iter = @tree.selection.selected
      if iter
        @selected_id = iter[0]
        refresh_detail
      end
    end

    @tree.signal_connect('row-activated') { do_edit }

    sw.add(@tree)
    left.pack_start(sw, expand: true, fill: true, padding: 0)
    left
  end

  def swap_detail(widget)
    @detail_sw.children.each { |c| @detail_sw.remove(c) }
    @detail_sw.add(widget)
    @detail_sw.show_all
  end

  def refresh_detail
    entry = @vault.find(@selected_id)
    if entry
      panel = build_detail_panel(
        entry,
        on_edit:   -> { do_edit },
        on_delete: -> { do_delete },
        on_copy:   ->(v, l) {
          clipboard_write(v)
          status_flash(@statusbar, @sb_ctx, "#{l} copied to clipboard")
        }
      )
      swap_detail(panel)
    else
      swap_detail(build_empty_detail)
    end
  end

  def refresh_list
    @store.clear
    entries = @vault.search(@search_query)
    entries.each do |e|
      iter    = @store.append
      iter[0] = e['id']
      iter[1] = e['name']
      iter[2] = e['username']
    end
    n = entries.size
    @count_lbl.text = "#{n} #{n == 1 ? 'entry' : 'entries'}"
  end

  def do_search(q)
    @search_query = q
    @selected_id  = nil
    refresh_list
    swap_detail(build_empty_detail)
  end

  def do_add
    vals = open_entry_dialog(@win)
    return unless vals
    @vault.add_entry(**vals)
    refresh_list
    status_flash(@statusbar, @sb_ctx, "Added '#{vals[:name]}'")
  end

  def do_edit
    return unless @selected_id
    entry = @vault.find(@selected_id)
    return unless entry
    vals = open_entry_dialog(@win, entry)
    return unless vals
    @vault.update_entry(@selected_id, **vals)
    refresh_list
    refresh_detail
    status_flash(@statusbar, @sb_ctx, "Updated '#{vals[:name]}'")
  end

  def do_delete
    return unless @selected_id
    entry = @vault.find(@selected_id)
    return unless entry
    return unless show_confirm_dialog(
      @win, "Delete '#{entry['name']}'?", 'This action cannot be undone.'
    )
    @vault.delete_entry(@selected_id)
    @selected_id = nil
    refresh_list
    swap_detail(build_empty_detail)
    status_flash(@statusbar, @sb_ctx, 'Entry deleted')
  end

  def do_lock
    GLib::Source.remove(@inactivity_timer) if @inactivity_timer
    @inactivity_timer = nil
    @vault.lock!
    @hbar.subtitle = 'Password Manager'
    @win.hide
    show_auth_screen
  end

  def show_auth_screen
    loop do
      if @vault.exists?
        # Enforce lockout before showing dialog
        if @locked_until && Time.now < @locked_until
          remaining = (@locked_until - Time.now).ceil
          show_error_dialog(nil, 'Vault is locked',
            "Too many failed attempts. Try again in #{format_remaining(remaining)}.")
          next
        end

        result = open_master_dialog

        case result
        when nil
          Gtk.main_quit
          return
        when :forgot
          open_forgot_dialog(@vault)
          next
        else
          un = result[:username]
          pw = result[:password]
          if @vault.unlock(un, pw)
            @login_attempts = 0
            @lockout_count  = 0
            @locked_until   = nil
            clear_lockout_state
            result[:remember] ? save_remembered_username(un) : clear_remembered_username
            break
          else
            @login_attempts += 1
            if @login_attempts >= MAX_LOGIN_ATTEMPTS
              @lockout_count += 1
              duration       = LOCKOUT_DURATIONS[[@lockout_count - 1, LOCKOUT_DURATIONS.length - 1].min]
              @locked_until  = Time.now + duration
              @login_attempts = 0
              save_lockout_state(@lockout_count, @locked_until)
              show_error_dialog(nil, 'Too many failed attempts',
                "Vault locked for #{format_duration(duration)}.")
            else
              left = MAX_LOGIN_ATTEMPTS - @login_attempts
              show_error_dialog(nil, 'Incorrect username or password',
                "#{left} attempt#{left == 1 ? '' : 's'} remaining before lockout.")
            end
          end
        end
      else
        setup_data = open_setup_dialog
        unless setup_data
          Gtk.main_quit
          return
        end
        @vault.create!(**setup_data)
        @login_attempts = 0
        @lockout_count  = 0
        @locked_until   = nil
        clear_lockout_state
        break
      end
    end

    @hbar.subtitle = "Welcome back, #{@vault.username}!"
    @win.show_all
    refresh_list
    reset_inactivity_timer
    msg = @vault.entries.empty? ?
      'Vault ready – click ＋ to add your first credential' :
      "#{@vault.entries.size} credential#{@vault.entries.size == 1 ? '' : 's'} loaded"
    status_flash(@statusbar, @sb_ctx, msg)
  end
end

# =============================================================================
# Entry Point
# =============================================================================
App.new.run