require 'pp'

require '../libgestalt/libgestalt.rb'

# This is all from the binary:
# .data:00007FF7784935A8 60 CB 11 78 F7 7F 00 00 dq offset a080000                       ; "080000"
# .data:00007FF7784935B0 06 00 00 00 00 00 00 00 dq 6
# .data:00007FF7784935B8 0E 00 00 00 00 00 00 00 dq 0Eh
# .data:00007FF7784935C0 21 00 00 00 00 00 00 00 dq 21h
# .data:00007FF7784935C8 05 00 00 00 00 00 00 00 dq 5
# .data:00007FF7784935D0 26 00 00 00 00 00 00 00 dq 26h
# .data:00007FF7784935D8 15 00 00 00 00 00 00 00 dq 15h
# .data:00007FF7784935E0 0B 00 00 00 00 00 00 00 dq 0Bh
# .data:00007FF7784935E8 00 00 00 00 00 00 00 00 dq 0
SERIAL_FUDGE_LIST= [0x0e, 0x21, 0x05, 0x26, 0x15, 0x0b]
SERIAL_FUDGE_VALUES = "080000"

gestalt = Gestalt.new('172.16.166.170')
ter = gestalt.get_ter()

puts "Received TER:"
pp ter

# Get the TER hash and convert to a byte array
value = ter[:args]['HASH'][:data].bytes

# Remove 6 values at 6 indices, which I think is obfuscation?
SERIAL_FUDGE_LIST.reverse.each_with_index do |c, i|
  fudge_value = SERIAL_FUDGE_VALUES.reverse[i].ord
  if value.delete_at(c) != fudge_value
    puts "Unexpected fudge value!"
    exit
  end
end

# Decode the value as base64
sha = Base64::decode64(value.map(&:chr).join)
puts "SHA256 of serial = #{ sha.unpack('H*').pop }"
puts

puts "Attempting to bruteforce it, though you may have more luck googling it..."
0.upto(0xffffffff).each do |i|
  if (i % 0x100000) == 0
    puts "Trying #{i}..."
  end

  if Digest::SHA256.digest(i.to_s) == sha
    puts "Found the serial: #{ i }"
    exit
  end
end

puts "Couldn't find the serial!"
