require 'pp'
require 'timeout'

require '../libgestalt/libgestalt.rb'

if ARGV[0]
  SEED = ARGV[0].to_i
  WRITE = false
else
  SEED = rand(0..0xffffffff)
  WRITE = true
end

puts "seed = #{SEED}"
srand(SEED)

if WRITE
  Dir.mkdir("out/#{SEED}", 0755) #=> 0
end
i = 0

#srand(1341)

# bits = [1290, 93, 324, 205, 147]

# test = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# license_str = [0x11111111, 0x0, 0x01, test].pack('VVVa*').unpack('H*').pop
# puts Gestalt.flip_bits(Gestalt.attach_header('' +
#   Gestalt.encode_bytes('DATA', license_str) +
#   '',
#   msgid: 0x13a
# ), [14]).unpack('H*')
# exit

loop do
  puts i
  compress = 0
  while rand < 0.5
    compress += 1
  end

  gestalt = Gestalt.new('172.16.166.170', compress: compress, fuzz: true)

  puts "Compress = #{compress}"
  begin
    Timeout::timeout(0.25) do
      packet = ''
      if rand() < 0.5
        packet = gestalt.attach_header(
          Gestalt.encode_bytes('PSWD', Gestalt.encrypt_password("NotMyPassword")) +
          Gestalt.encode_str('ADLN', "NotMyUsername") +
          Gestalt.encode_int('AMID', Gestalt::LOGIN_ETR),
          msgid: 0x01,
        )
      else
        test = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        license_str = [0x11111111, 0x0, 0x01, test].pack('VVVa*').unpack('H*').pop


        packet = gestalt.attach_header(
          Gestalt.encode_bytes('DATA', license_str),
          msgid: 0x13a,
        )
      end

      puts "Sending: #{ packet.unpack('H*') }"

      if WRITE
        File.write("out/#{SEED}/#{i}", packet)
      end
      i += 1
      gestalt.s.write(packet)
      gestalt.receive_message()
    end
  rescue StandardError => e
    puts "Exception: #{e}"
    puts e.backtrace
  ensure
    gestalt.close
  end
end
