require 'pcap'
require '../libgestalt/libgestalt.rb'

if !ARGV[0]
  puts "Usage: #{ $0 } <file.pcap> [port]"
  exit 1
end

PORT = ARGV[1] || 1100

def check_data(data)
  while data.length > 4
    length, data = data.unpack('Va*')

    if data.length < length - 4
      raise "Invalid length field! Expected #{length} bytes, but only #{data.length} remain!"
    end

    message, data = data.unpack("a#{length - 4}a*")

    begin
      parsed = Gestalt::parse_packet([length, message].pack('Va*'))
      if parsed[:msgid] == Gestalt::MSGID_LOGIN
        if parsed[:args]['PSWD']
          #pp parsed
          decrypted = Gestalt::decrypt_password(parsed[:args]['PSWD'][:data])
          puts "Found login: #{ parsed[:args]['ADLN'][:data] } / #{ decrypted } (type = \"#{ parsed[:args]['AMID'][:data_str] }\")"
          if parsed[:args]['BUFF']
            puts " NTLMSSP blob: #{ parsed[:args]['BUFF'][:data].unpack('H*') }"
          end
        end
      end
    rescue StandardError => e
      puts "Failed to parse packet: #{e}"
      puts e.backtrace
    end
  end
end

begin
  pcap = Pcap::Capture.open_offline(ARGV[0])

  incoming = ''
  outgoing = ''

  pcap.loop(-1) do |pkt|
    if pkt.tcp? && pkt.tcp_data_len > 0
      if pkt.tcp_dport == PORT
        outgoing.concat(pkt.tcp_data)
      elsif pkt.tcp_sport == PORT
        incoming.concat(pkt.tcp_data)
      end
    end
  end

  check_data(outgoing)
  #check_data(incoming)
ensure
  pcap.close if pcap
end
