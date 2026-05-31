#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# SecureVault Password Manager
# GUI: GTK3 | Encryption: AES-256-CBC | Key Derivation: PBKDF2-HMAC-SHA256
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
PBKDF2_ITERATIONS = 100_000        # NIST recommended minimum
KEY_BYTES         = 32             # 256-bit key for AES-256
SALT_BYTES        = 32             # 256-bit random salt
IV_BYTES          = 16             # 128-bit AES block size
VAULT_DIR         = File.join(Dir.home, '.securevault')
VAULT_FILE        = File.join(VAULT_DIR, 'vault.dat')
SALT_FILE         = File.join(VAULT_DIR, 'vault.salt')
APP_TITLE         = 'SecureVault'

# =============================================================================
# Crypto – AES-256-CBC with PBKDF2-HMAC-SHA256 key derivation
# =============================================================================
module Crypto
  # Derives a 256-bit key from the master password using PBKDF2-HMAC-SHA256.
  # This is significantly stronger than a raw SHA-256 hash because it is
  # intentionally slow (100k iterations), making brute-force attacks expensive.
  def self.derive_key(password, salt)
    OpenSSL::PKCS5.pbkdf2_hmac(
      password,
      salt,
      PBKDF2_ITERATIONS,
      KEY_BYTES,
      OpenSSL::Digest::SHA256.new
    )
  end

  # Encrypts plaintext with AES-256-CBC. Prepends a random IV to the ciphertext
  # and returns the whole payload as a Base64 string.
  def self.encrypt(plaintext, key)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    iv         = cipher.random_iv
    cipher.key = key
    ciphertext = cipher.update(plaintext.encode('UTF-8')) + cipher.final
    Base64.strict_encode64(iv + ciphertext)
  end

  # Decrypts a Base64-encoded payload produced by #encrypt.
  def self.decrypt(encoded, key)
    raw        = Base64.strict_decode64(encoded)
    iv         = raw[0, IV_BYTES]
    ciphertext = raw[IV_BYTES..]
    cipher     = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.decrypt
    cipher.key = key
    cipher.iv  = iv
    cipher.update(ciphertext) + cipher.final
  rescue OpenSSL::Cipher::CipherError
    raise ArgumentError, 'Decryption failed – wrong password or corrupted data'
  end
end

# =============================================================================
# Vault – Encrypted JSON credential store on disk
# =============================================================================
class Vault
  attr_reader :entries

  def initialize
    @entries = []
    @key     = nil
    FileUtils.mkdir_p(VAULT_DIR)
  end

  def exists?  = File.exist?(VAULT_FILE) && File.exist?(SALT_FILE)
  def locked?  = @key.nil?

  # Creates a brand-new vault protected by +password+.
  def create!(password)
    salt = OpenSSL::Random.random_bytes(SALT_BYTES)
    File.binwrite(SALT_FILE, salt)
    @key     = Crypto.derive_key(password, salt)
    @entries = []
    persist!
  end

  # Unlocks the existing vault. Returns true on success, false on wrong password.
  def unlock(password)
    return false unless exists?
    salt      = File.binread(SALT_FILE)
    candidate = Crypto.derive_key(password, salt)
    raw       = Crypto.decrypt(File.read(VAULT_FILE, encoding: 'UTF-8'), candidate)
    @entries  = JSON.parse(raw)
    @key      = candidate
    true
  rescue ArgumentError, JSON::ParserError
    false
  end

  def lock!
    @entries = []
    @key     = nil
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

  def persist!
    raise 'Vault is locked' if locked?
    File.write(VAULT_FILE, Crypto.encrypt(JSON.generate(@entries), @key), encoding: 'UTF-8')
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
    (required + fill).shuffle { SecureRandom.random_number }.join
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
# Utility helpers (module-level, used throughout)
# =============================================================================

def esc(str)
  str.to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;').gsub('"', '&quot;')
end

def clipboard_write(text)
  Gtk::Clipboard.get(Gdk::Selection::CLIPBOARD).text = text.to_s
end

def status_flash(statusbar, ctx_id, msg, seconds: 4)
  statusbar.push(ctx_id, msg)
  GLib::Timeout.add(seconds * 1000) { statusbar.pop(ctx_id); false }
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
# Password Generator Dialog
# =============================================================================
def open_generator_dialog(parent)
  d = Gtk::Dialog.new(
    title: 'Password Generator',
    parent: parent,
    flags: [:modal, :destroy_with_parent]
  )
  d.set_default_size(400, 295)

  area = d.child
  area.margin = 16
  area.spacing = 8

  # Length row
  len_box = Gtk::Box.new(:horizontal, 8)
  lbl = Gtk::Label.new('Length:')
  lbl.xalign = 1.0
  lbl.width_chars = 10
  len_spin = Gtk::SpinButton.new_with_range(8, 64, 1)
  len_spin.value = 16
  len_box.pack_start(lbl,      expand: false, fill: false, padding: 0)
  len_box.pack_start(len_spin, expand: false, fill: false, padding: 0)
  area.pack_start(len_box, expand: false, fill: false, padding: 0)

  # Option checkboxes
  upper_cb   = Gtk::CheckButton.new(label: 'Uppercase letters  (A–Z)')
  digits_cb  = Gtk::CheckButton.new(label: 'Digits  (0–9)')
  symbols_cb = Gtk::CheckButton.new(label: 'Symbols  (!@#$…)')
  [upper_cb, digits_cb, symbols_cb].each do |cb|
    cb.active = true
    area.pack_start(cb, expand: false, fill: false, padding: 0)
  end

  area.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 4)

  # Preview row
  prev_row = Gtk::Box.new(:horizontal, 6)
  prev_e   = Gtk::Entry.new
  prev_e.editable = false
  prev_e.hexpand  = true
  prev_e.style_context.add_class('monospace')
  regen_btn = Gtk::Button.new(label: '↺  New')
  regen_btn.tooltip_text = 'Generate another'
  prev_row.pack_start(prev_e,    expand: true,  fill: true,  padding: 0)
  prev_row.pack_start(regen_btn, expand: false, fill: false, padding: 0)
  area.pack_start(prev_row, expand: false, fill: false, padding: 0)

  regenerate = lambda {
    prev_e.text = PasswordGen.generate(
      length:  len_spin.value.to_i,
      upper:   upper_cb.active?,
      digits:  digits_cb.active?,
      symbols: symbols_cb.active?
    )
  }

  regen_btn.signal_connect('clicked')       { regenerate.call }
  len_spin.signal_connect('value-changed')  { regenerate.call }
  [upper_cb, digits_cb, symbols_cb].each { |cb| cb.signal_connect('toggled') { regenerate.call } }
  regenerate.call

  d.add_button('Cancel', Gtk::ResponseType::CANCEL)
  ok_btn = d.add_button('Use This Password', Gtk::ResponseType::OK)
  ok_btn.style_context.add_class('suggested-action')
  d.default_response = Gtk::ResponseType::OK
  d.show_all

  result = nil
  result = prev_e.text if d.run == Gtk::ResponseType::OK
  d.destroy
  result
end

# =============================================================================
# Master Password Dialog  (new vault creation OR unlock)
# =============================================================================
def open_master_dialog(new_vault:, error_msg: nil)
  d = Gtk::Dialog.new(
    title:  new_vault ? 'Create New Vault' : "Unlock #{APP_TITLE}",
    parent: nil,
    flags:  []
  )
  d.set_default_size(430, new_vault ? 275 : 215)
  d.set_position(:center)
  d.deletable = false

  area = d.child
  area.margin = 20
  area.spacing = 12

  # Icon + heading
  top  = Gtk::Box.new(:horizontal, 14)
  icon = Gtk::Image.new(icon_name: 'system-lock-screen', icon_size: :dialog)
  top.pack_start(icon, expand: false, fill: false, padding: 0)

  hbox    = Gtk::Box.new(:vertical, 4)
  title_l = Gtk::Label.new
  title_l.markup = new_vault ?
    '<b><big>Create Your Vault</big></b>' :
    '<b><big>Unlock Your Vault</big></b>'
  title_l.xalign = 0

  sub_l = Gtk::Label.new
  sub_l.markup = new_vault ?
    '<small>Choose a strong master password. It cannot be recovered if lost.</small>' :
    '<small>Enter your master password to access your credentials.</small>'
  sub_l.xalign = 0
  sub_l.wrap   = true

  hbox.pack_start(title_l, expand: false)
  hbox.pack_start(sub_l,   expand: false)
  top.pack_start(hbox, expand: true, fill: true, padding: 0)
  area.pack_start(top,                         expand: false, fill: false, padding: 0)
  area.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 0)

  make_row = lambda { |label_text, entry_widget|
    row = Gtk::Box.new(:horizontal, 8)
    l = Gtk::Label.new(label_text)
    l.width_chars = 10
    l.xalign      = 1.0
    row.pack_start(l,            expand: false, fill: false, padding: 0)
    row.pack_start(entry_widget, expand: true,  fill: true,  padding: 0)
    row
  }

  pass_e = Gtk::Entry.new
  pass_e.visibility       = false
  pass_e.placeholder_text = 'Master password'
  pass_e.activates_default = true
  pass_e.hexpand = true
  area.pack_start(make_row.call('Password:', pass_e), expand: false, fill: false, padding: 0)

  confirm_e = nil
  if new_vault
    confirm_e = Gtk::Entry.new
    confirm_e.visibility        = false
    confirm_e.placeholder_text  = 'Confirm password'
    confirm_e.activates_default = true
    confirm_e.hexpand = true
    area.pack_start(make_row.call('Confirm:', confirm_e), expand: false, fill: false, padding: 0)
  end

  err_lbl = Gtk::Label.new
  err_lbl.xalign = 0
  err_lbl.markup = "<span foreground='red'>#{esc error_msg}</span>" if error_msg
  area.pack_start(err_lbl, expand: false, fill: false, padding: 0)

  d.add_button('Quit', Gtk::ResponseType::CANCEL)
  ok_btn = d.add_button(new_vault ? 'Create Vault' : 'Unlock', Gtk::ResponseType::OK)
  ok_btn.style_context.add_class('suggested-action')
  d.default_response = Gtk::ResponseType::OK
  d.show_all

  loop do
    resp = d.run
    unless resp == Gtk::ResponseType::OK
      d.destroy
      return nil
    end

    pw = pass_e.text

    if pw.empty?
      err_lbl.markup = "<span foreground='red'>⚠ Password cannot be empty</span>"
      next
    end
    if new_vault
      if pw.length < 8
        err_lbl.markup = "<span foreground='red'>⚠ Minimum 8 characters required</span>"
        next
      end
      if pw != confirm_e.text
        err_lbl.markup = "<span foreground='red'>⚠ Passwords do not match</span>"
        next
      end
    end

    d.destroy
    return pw
  end
end

# =============================================================================
# Credential Form Dialog (Add / Edit)
# =============================================================================
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

  # Grid for labeled fields
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
  pass_row.pack_start(pass_e,    expand: true,  fill: true,  padding: 0)
  pass_row.pack_start(show_btn,  expand: false, fill: false, padding: 0)
  pass_row.pack_start(gen_btn,   expand: false, fill: false, padding: 0)
  pass_row.hexpand = true

  rows = [
    ['Name *',     name_e],
    ['Username *', user_e],
    ['Password *', pass_row],
    ['URL',        url_e],
  ]

  rows.each_with_index do |(label_text, widget), i|
    l = Gtk::Label.new(label_text)
    l.xalign      = 1.0
    l.width_chars = 12
    grid.attach(l,      0, i, 1, 1)
    grid.attach(widget, 1, i, 1, 1)
  end

  area.pack_start(grid, expand: false, fill: false, padding: 0)

  # Notes text area
  notes_lbl = Gtk::Label.new('Notes')
  notes_lbl.xalign = 0
  area.pack_start(notes_lbl, expand: false, fill: false, padding: 0)

  notes_buf = Gtk::TextBuffer.new
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

  # Pre-populate when editing
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
# Detail Panel – builds the right-side credential view
# =============================================================================
def build_detail_panel(entry, on_edit:, on_delete:, on_copy:)
  outer = Gtk::Box.new(:vertical, 0)

  scroll = Gtk::ScrolledWindow.new
  scroll.set_policy(:never, :automatic)
  scroll.hexpand = true
  scroll.vexpand = true

  content = Gtk::Box.new(:vertical, 0)
  content.margin = 20
  content.spacing = 14

  # Title row
  hdr      = Gtk::Box.new(:horizontal, 12)
  hdr_icon = Gtk::Image.new(icon_name: 'dialog-password', icon_size: :large_toolbar)
  name_lbl = Gtk::Label.new
  name_lbl.markup    = "<b><big>#{esc entry['name']}</big></b>"
  name_lbl.xalign    = 0
  name_lbl.hexpand   = true
  name_lbl.ellipsize = :end
  hdr.pack_start(hdr_icon, expand: false, fill: false, padding: 0)
  hdr.pack_start(name_lbl, expand: true,  fill: true,  padding: 0)
  content.pack_start(hdr,                              expand: false, fill: false, padding: 0)
  content.pack_start(Gtk::Separator.new(:horizontal),  expand: false, fill: false, padding: 0)

  # Credential fields
  [
    ['USERNAME', entry['username'], false],
    ['PASSWORD', entry['password'], true],
    ['URL',      entry['url'],      false],
  ].each do |field_label, value, secret|
    next if value.nil? || value.strip.empty?

    fbox = Gtk::Box.new(:vertical, 4)

    lbl = Gtk::Label.new
    lbl.markup = "<small><b>#{esc field_label}</b></small>"
    lbl.xalign = 0
    lbl.style_context.add_class('field-label')
    fbox.pack_start(lbl, expand: false, fill: false, padding: 0)

    row = Gtk::Box.new(:horizontal, 4)

    if secret
      val_e          = Gtk::Entry.new
      val_e.text     = value
      val_e.visibility = false
      val_e.editable = false
      val_e.hexpand  = true
      val_e.style_context.add_class('monospace')

      show_btn = Gtk::ToggleButton.new
      show_btn.image        = Gtk::Image.new(icon_name: 'view-reveal-symbolic', icon_size: :button)
      show_btn.tooltip_text = 'Show / Hide'
      show_btn.signal_connect('toggled') { |b| val_e.visibility = b.active? }

      copy_btn = Gtk::Button.new
      copy_btn.image        = Gtk::Image.new(icon_name: 'edit-copy-symbolic', icon_size: :button)
      copy_btn.tooltip_text = "Copy #{field_label.capitalize}"
      copy_btn.signal_connect('clicked') { on_copy.call(value, field_label.capitalize) }

      row.pack_start(val_e,     expand: true,  fill: true,  padding: 0)
      row.pack_start(show_btn,  expand: false, fill: false, padding: 0)
      row.pack_start(copy_btn,  expand: false, fill: false, padding: 0)
    else
      val_lbl           = Gtk::Label.new(value)
      val_lbl.xalign    = 0
      val_lbl.selectable = true
      val_lbl.ellipsize = :end
      val_lbl.hexpand   = true

      copy_btn = Gtk::Button.new
      copy_btn.image        = Gtk::Image.new(icon_name: 'edit-copy-symbolic', icon_size: :button)
      copy_btn.tooltip_text = "Copy #{field_label.capitalize}"
      copy_btn.signal_connect('clicked') { on_copy.call(value, field_label.capitalize) }

      row.pack_start(val_lbl,  expand: true,  fill: true,  padding: 0)
      row.pack_start(copy_btn, expand: false, fill: false, padding: 0)
    end

    fbox.pack_start(row, expand: false, fill: false, padding: 0)
    content.pack_start(fbox, expand: false, fill: false, padding: 0)
  end

  # Notes
  unless entry['notes'].to_s.strip.empty?
    nbox = Gtk::Box.new(:vertical, 4)
    n_lbl = Gtk::Label.new
    n_lbl.markup = '<small><b>NOTES</b></small>'
    n_lbl.xalign = 0
    n_lbl.style_context.add_class('field-label')
    n_text = Gtk::Label.new(entry['notes'])
    n_text.xalign     = 0
    n_text.wrap       = true
    n_text.selectable = true
    nbox.pack_start(n_lbl,  expand: false)
    nbox.pack_start(n_text, expand: false)
    content.pack_start(nbox, expand: false, fill: false, padding: 0)
  end

  # Timestamp
  ts_lbl = Gtk::Label.new
  ts_lbl.markup = "<small><span foreground='gray'>Updated: #{esc entry['updated_at']}</span></small>"
  ts_lbl.xalign = 0
  content.pack_start(ts_lbl, expand: false, fill: false, padding: 0)

  scroll.add(content)
  outer.pack_start(scroll, expand: true, fill: true, padding: 0)

  # Action buttons
  btn_bar = Gtk::Box.new(:horizontal, 8)
  btn_bar.halign        = :center
  btn_bar.margin_top    = 4
  btn_bar.margin_bottom = 12

  edit_btn = Gtk::Button.new(label: ' Edit')
  edit_btn.image           = Gtk::Image.new(icon_name: 'document-edit-symbolic', icon_size: :button)
  edit_btn.always_show_image = true
  edit_btn.signal_connect('clicked') { on_edit.call }

  del_btn = Gtk::Button.new(label: ' Delete')
  del_btn.image           = Gtk::Image.new(icon_name: 'user-trash-symbolic', icon_size: :button)
  del_btn.always_show_image = true
  del_btn.style_context.add_class('destructive-action')
  del_btn.signal_connect('clicked') { on_delete.call }

  btn_bar.pack_start(edit_btn, expand: false)
  btn_bar.pack_start(del_btn,  expand: false)
  outer.pack_start(btn_bar, expand: false, fill: false, padding: 0)

  outer
end

def build_empty_detail
  box = Gtk::Box.new(:vertical, 14)
  box.valign  = :center
  box.halign  = :center
  box.vexpand = true
  box.hexpand = true

  img = Gtk::Image.new(icon_name: 'system-lock-screen', icon_size: :dialog)
  lbl = Gtk::Label.new
  lbl.markup  = "<span foreground='gray'>Select a credential to view its details\nor click <b>＋</b> to add a new one.</span>"
  lbl.justify = :center
  lbl.wrap    = true

  box.pack_start(img, expand: false)
  box.pack_start(lbl, expand: false)
  box
end

# =============================================================================
# Main Application
# =============================================================================
class App
  def initialize
    @vault        = Vault.new
    @selected_id  = nil
    @search_query = ''
    apply_css
    build_window
    show_auth_screen
  end

  def run
    Gtk.main
  end

  # ── Private ────────────────────────────────────────────────────────────────
  private

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

    # ── Header bar ─────────────────────────────────────────────────────────
    hbar = Gtk::HeaderBar.new
    hbar.title               = APP_TITLE
    hbar.subtitle            = 'Password Manager'
    hbar.show_close_button   = true
    @win.set_titlebar(hbar)

    @add_btn = Gtk::Button.new
    @add_btn.image        = Gtk::Image.new(icon_name: 'list-add-symbolic', icon_size: :button)
    @add_btn.tooltip_text = 'Add credential  (Ctrl+N)'
    @add_btn.signal_connect('clicked') { do_add }
    hbar.pack_start(@add_btn)

    lock_btn = Gtk::Button.new
    lock_btn.image        = Gtk::Image.new(icon_name: 'changes-prevent-symbolic', icon_size: :button)
    lock_btn.tooltip_text = 'Lock vault  (Ctrl+L)'
    lock_btn.signal_connect('clicked') { do_lock }
    hbar.pack_end(lock_btn)

    @count_lbl = Gtk::Label.new('0 entries')
    hbar.pack_end(@count_lbl)

    # ── Root layout ────────────────────────────────────────────────────────
    root = Gtk::Box.new(:vertical, 0)

    # Search bar
    sbar = Gtk::Box.new(:horizontal, 8)
    sbar.margin = 8
    @search_e = Gtk::SearchEntry.new
    @search_e.placeholder_text = 'Search by name, username or URL…'
    @search_e.hexpand = true
    @search_e.signal_connect('search-changed') { |e| do_search(e.text) }
    sbar.pack_start(@search_e, expand: true, fill: true, padding: 0)
    root.pack_start(sbar, expand: false, fill: false, padding: 0)
    root.pack_start(Gtk::Separator.new(:horizontal), expand: false, fill: false, padding: 0)

    # Paned: list | detail
    @paned = Gtk::Paned.new(:horizontal)
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

    # Status bar
    @statusbar = Gtk::Statusbar.new
    @sb_ctx    = @statusbar.get_context_id('app')
    root.pack_start(@statusbar, expand: false, fill: false, padding: 0)

    @win.add(root)

    # Keyboard shortcuts
    @win.signal_connect('key-press-event') do |_, ev|
      if ev.state.control_mask?
        case ev.keyval
        when Gdk::Keyval::KEY_n then do_add
        when Gdk::Keyval::KEY_l then do_lock
        when Gdk::Keyval::KEY_f then @search_e.grab_focus
        end
      end
    end
  end

  def build_list_panel
    left = Gtk::Box.new(:vertical, 0)
    left.set_size_request(245, -1)

    sw = Gtk::ScrolledWindow.new
    sw.set_policy(:never, :automatic)
    sw.vexpand = true

    # ListStore: id | name | username
    @store = Gtk::ListStore.new(String, String, String)

    @tree = Gtk::TreeView.new(@store)
    @tree.headers_visible       = false
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

  # Replaces the content of the detail scroll window
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

  # ── Actions ────────────────────────────────────────────────────────────────

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
    @vault.lock!
    @win.hide
    show_auth_screen
  end

  # ── Auth flow ──────────────────────────────────────────────────────────────

  def show_auth_screen
    loop do
      pw = open_master_dialog(new_vault: !@vault.exists?)
      unless pw
        Gtk.main_quit
        return
      end

      if @vault.exists?
        if @vault.unlock(pw)
          break
        else
          show_error_dialog(nil, 'Incorrect master password', 'Please try again.')
        end
      else
        @vault.create!(pw)
        break
      end
    end

    @win.show_all
    refresh_list
    status_flash(@statusbar, @sb_ctx,
      @vault.entries.empty? ? 'Vault ready – click ＋ to add your first credential' : 'Vault unlocked')
  end
end

# =============================================================================
# Entry Point
# =============================================================================
App.new.run
