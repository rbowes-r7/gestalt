require 'socket'
require 'twofish'
require 'pp'
require 'base64'
require 'digest'
require 'rc4'
require 'zlib'

class Gestalt
  MSGID_LOGIN = 0x01
  MSGID_GET_SETTINGS = 0x0c
  MSGID_GET_SITES = 0x2c
  MSGID_CHANGE_PASSWORD = 0x4d
  MSGID_GET_TER = 0x138 # Trial Extension Request
  MSGID_REGISTER_COMMAND = 0x99
  MSGID_DELETE_COMMAND = 0x9a
  MSGID_GET_DATA = 0x173
  MSGID_COMPRESSED = 0xff7f

  LOGIN_ETR = 0
  LOGIN_LOGGED_IN_USER = 1
  LOGIN_WINDOWS = 2
  LOGIN_ARCUS = 3

  ERRORS = {
    0 => "Success",
    7 => "Parsing error",
    11 => "Login failed",
    52 => "Command not found",
    65280 => "Command already exists",
  }

  # As far as I can tell, the protocol doesn't have any way to properly tell
  # the type of each field, and instead hardcodes the parsers. Thankfully, they
  # have a length field so we can handle unknowns!
  TYPES = {
    'AMID' => {
      name: "Login type",
      type: :int32,
      values: {
        0 => "EFT Authentication",
        1 => "Currently logged on user",
        2 => "Windows authentication",
        3 => "Arcus RDGW",
      },
    },
    'PSWD' => {
      name: "Encrypted password",
      type: :bytes,
    },
    'ADLN' => {
      name: "Username",
      type: :string,
    },
  }

  attr_accessor :s

  def self.decrypt_password(b)
    # Static 5-byte key for extra security
    tf = Twofish.new("tfgry\0\0\0\0\0\0\0\0\0\0\0", :padding => :zero_byte, :mode => :cbc)

    # By default, the library randomizes the IV, so set it specifically
    tf.iv = "\0" * 16

    # We need to append a NUL byte, because this is UTF-16 and zero-padded, which
    # means the final character is truncated (lol)
    return (tf.decrypt(b) + "\0").force_encoding("UTF-16LE").encode("ASCII-8BIT")
  end

  def self.encrypt_password(pw)
    # Encode as UTF-16
    pw = pw.encode("UTF-16LE")

    # Static 5-byte key for extra security
    tf = Twofish.new("tfgry\0\0\0\0\0\0\0\0\0\0\0", :padding => :zero_byte, :mode => :cbc)

    # By default, the library randomizes the IV, so set it specifically
    tf.iv = "\0" * 16

    return tf.encrypt(pw)
  end

  def self.encode_type5(name, value)
    return [name, 5, value.length, value].pack('a4VVa*')
  end

  def self.encode_int(name, value, unk1: 5)
    return encode_type5(name, [value].pack('V'))
  end

  def self.encode_str(name, value, unk1: 5, length: nil)
    length = length.nil? ? -(value.length + 1) : length

    # Create the "data" portion
    str = [length, *value.bytes].pack('Vv*')

    return encode_type5(name, str)
  end

  def self.encode_uuid(name, value, unk1: 5)
    return encode_type5(name, value)
  end

  def self.encode_bytes(name, value, unk1: 5, length: nil)
    length = length.nil? ? value.length : length

    # Create the "data" portion
    str = [length, value].pack('Va*')

    return encode_type5(name, str)
  end

  def self.encode_array(name, value, unk1: 5)
    # Observed that it starts with a 1 - possibly this is an array size?
    out = [1].pack('V')

    # Encode the fields
    value.each do |v|
      case v[:type]
      when :string
        out.concat([(~v[:value].length) & 0x0FFFFFFFF, *v[:value].bytes].pack('Vv*'))
      when :int32
        out.concat([v[:value]].pack('V'))
      when :uuid_array
        out.concat([v[:value].length].pack('V'))
        v[:value].each do |uuid|
          out.concat([uuid].pack('a16'))
        end
      else
        raise "Unknown type in array: #{ v[:type] }"
      end
    end

    # Prepend the name + unk1 + length
    out = [name, unk1, out.length, out].pack('a4VVa*')

    return out
  end

  def self.do_compress(message)
    message = Zlib::deflate(message)

    return [message.length + 8, MSGID_COMPRESSED, message].pack('VVa*')
  end

  def self.flip_bits(message, bits)
    message = message.unpack('b*').pop

    bits.each do |bit|
      puts "bit = #{bit}"
      if message[bit] == '0'
        message[bit] = '1'
      else
        message[bit] = '0'
      end
    end

    return [message].pack('b*')
  end

  def self.fuzz(message)
    changes = 5 - Math.log10(rand(0..100000)).floor

    return flip_bits(message, 1.upto(changes).map { rand(0..message.length) })
  end

  def attach_header(data, msgid: 1)
    message = [data.length + 8, msgid, data].pack('VVa*')

    0.upto(@compress - 1) do
      if @fuzz
        message = Gestalt.fuzz(message)
      end

      message = Gestalt.do_compress(message)
    end

    if @fuzz
      message = Gestalt.fuzz(message)
    end

    return message
  end

  def self.parse_packet(p)
    File.write('/tmp/packet', p)
    length, msgid, body = p.unpack('VVa*')

    # Start building the result
    result = {
      length: length,
      msgid: msgid,
      # body: body,
      args: {}
    }

    # 0xff7f is a compressed packet - do what they do and recurse
    if msgid == MSGID_COMPRESSED
      puts "Compressed message!"

      return self.parse_packet(Zlib::inflate(body))
    end

    # Parse all the parameters
    loop do
      # Stop when the body length is too short
      if body.length < 4
        break
      end

      # Each field appears to start with a 4-byte name then 4-byte type
      name, type, body = body.unpack('a4Va*')

      # Type 1 = a 4-byte integer
      if type == 1
        if body.length < 4
          raise "Can't parse integer, we ran out of data!"
        end

        value, body = body.unpack('Va*')
        result[:args][name] = {
          type: :int,
          value: value,
        }

      # Type 5 = variable types, it seems
      elsif type == 5
        # There's always a 4-byte length
        if body.length < 4
          raise "Can't parse byte array length, we ran out of data!"
        end

        length, body = body.unpack('Va*')
        if body.length < length
          raise "Can't parse byte array, the size (#{ length }) would go off the end of the remaining body (#{ body.length })!"
        end

        # Get the data
        data, body = body.unpack("a#{length}a*")

        # From here, we don't necessarily know what to do next - consult the
        # list of stuff we've identified, or just do our best
        type = TYPES[name]
        if type
          if type[:type] == :int32
            value, data = data.unpack('Va*')

            if type[:values]
              result[:args][name] = {
                type: type[:type],
                length: 4,
                data: value,
                data_str: type[:values][value] || "Unknown: #{ value }",
                name: type[:name],
              }
            else
              result[:args][name] = {
                type: type[:type],
                length: 4,
                data: value,
                name: type[:name],
              }
            end
          elsif type[:type] == :string
            # These are prefixed with a negative length
            other_length, data = data.unpack('Va*')
            if (other_length & 0x80000000) == 0
              raise "Length is supposed to be negative for name #{name}: 0x#{length.to_s(16)}"
            end

            other_length = (~other_length) & 0x0FFFFFFFF

            # Read the data at UTF16, followed by the rest of the data, then pop it off
            value = data.unpack("v#{other_length}a*")
            data = value.pop

            # Convert to characters
            value = value.map(&:chr).join

            result[:args][name] = {
              type: type[:type],
              length: other_length,
              data: value,
              name: type[:name],
            }
          elsif type[:type] == :bytes
            # This is prefixed with a positive length
            other_length, data = data.unpack('Va*')
            if (other_length & 0x80000000) != 0
              raise "Length is not supposed to be negative for name #{name}: 0x#{other_length.to_s(16)}"
            end

            # Read the data at UTF16, followed by the rest of the data, then pop it off
            value, data = data.unpack("a#{other_length}a*")

            result[:args][name] = {
              type: type[:type],
              length: other_length,
              data: value,
              name: type[:name],
            }
          else
            raise "We are trying to use an unidentified type for name #{ name }: #{ type[:type] }"
          end

          if data != ''
            $stderr.puts "WARNING: Unparsed data: #{ data.unpack('H*') }"
          end
        else
          # Do our best!
          result[:args][name] = {
            type: :unknown,
            length: length,
            data: data,
            name: name,
          }
        end
      elsif type == 4 # It seems like a utf-16 array
        if body.length < 4
          raise "Can't parse UTF16 string length, we ran out of data!"
        end

        length, body = body.unpack('Va*')
        if body.length < length
          raise "Can't parse UTF16 string, the size (#{ length }) would go off the end of the remaining body (#{ body.length })!"
        end

        # Reads the UTF16 string + whatever is after it
        data = body.unpack("v#{length}a*")
        body = data.pop # Get the last element (the body)

        result[:args][name] = {
          type: :string,
          length: length,
          data: data.pack('C*'),
        }
      else
        raise "Unknown value for type: #{ type }"
      end
    end

    return result
  end

  def receive_message()
    header = @s.recv(4)
    if !header || header.length != 4
      raise "Couldn't receive the header!"
    end

    length = header.unpack('V').pop

    body = @s.recv(length - 4)
    if !body || body.length != length - 4
      raise "Couldn't receive the body!"
    end

    # We need to parse it with the length attached, because compressed packets
    # want recursion
    result = Gestalt.parse_packet(header + body)

    return result
  end

  def send_recv(msgid, packet)
    packet = attach_header(packet, msgid: msgid)
    puts "Sending: #{ packet.unpack('H*') }"
    @s.write(packet)
    return receive_message()
  end

  def get_sites()
    data = send_recv(MSGID_GET_SITES, '')
    data = data[:args]['USRS'][:data]
    length, data = data.unpack('Va*')
    puts length

    sites = []
    1.upto(length) do
      site, unk_00000000, data = data.unpack('a16Va*')
      sites << site
    end

    return sites
  end

  def initialize(host, port = 1100, fuzz: false, compress: 0)
    @s = TCPSocket.new(host, port)
    @fuzz = fuzz
    @compress = compress

    return receive_message()
  end

  def authenticate(username, password, login_type = LOGIN_ETR)
    return send_recv(MSGID_LOGIN, '' +
      Gestalt.encode_bytes('PSWD', Gestalt.encrypt_password(password)) +
      Gestalt.encode_str('ADLN', username) +
      Gestalt.encode_int('AMID', login_type)
    )
  end

  def get_ter()
    return send_recv(MSGID_GET_TER, '')
  end

  def close
    if @s
      @s.close
      @s = nil
    end
  end
end
