use aiken/builtin

pub type Recipient {
  Account(ByteArray)
  Utxo(ByteArray)
}

pub fn encode(recipient: Recipient) -> ByteArray {
  when recipient is {
    Account(key) -> {
      expect builtin.length_of_bytearray(key) == 32
      builtin.append_bytearray(#"820182005820", key)
    }
    Utxo(key) -> {
      expect builtin.length_of_bytearray(key) == 32
      builtin.append_bytearray(#"8201820182005820", key)
    }
  }
}

pub fn decode(bytes: ByteArray) -> Option<Recipient> {
  if builtin.length_of_bytearray(bytes) == 38 && builtin.slice_bytearray(
    0,
    6,
    bytes,
  ) == #"820182005820" {
    Some(Account(builtin.slice_bytearray(6, 32, bytes)))
  } else if builtin.length_of_bytearray(bytes) == 40 && builtin.slice_bytearray(
    0,
    8,
    bytes,
  ) == #"8201820182005820" {
    Some(Utxo(builtin.slice_bytearray(8, 32, bytes)))
  } else {
    None
  }
}

test account_roundtrip() {
  let key = #"1111111111111111111111111111111111111111111111111111111111111111"
  let bytes = #"8201820058201111111111111111111111111111111111111111111111111111111111111111"
  and {
    encode(Account(key)) == bytes,
    decode(bytes) == Some(Account(key)),
  }
}

test utxo_roundtrip() {
  let key = #"2222222222222222222222222222222222222222222222222222222222222222"
  let bytes = #"82018201820058202222222222222222222222222222222222222222222222222222222222222222"
  and {
    encode(Utxo(key)) == bytes,
    decode(bytes) == Some(Utxo(key)),
  }
}

test rejects_reserved() {
  decode(
    #"8201820258201111111111111111111111111111111111111111111111111111111111111111",
  ) == None
}

test rejects_unknown_variant() {
  decode(
    #"8201820358201111111111111111111111111111111111111111111111111111111111111111",
  ) == None
}

test rejects_unknown_version() {
  decode(
    #"8202820058201111111111111111111111111111111111111111111111111111111111111111",
  ) == None
}

test rejects_short_key() {
  decode(
    #"82018200581f11111111111111111111111111111111111111111111111111111111111111",
  ) == None
}

test rejects_trailing_bytes() {
  decode(
    #"820182005820111111111111111111111111111111111111111111111111111111111111111100",
  ) == None
}

test rejects_noncanonical_integer() {
  decode(
    #"821801820058201111111111111111111111111111111111111111111111111111111111111111",
  ) == None
}

test rejects_unknown_lock() {
  decode(
    #"82018201820158202222222222222222222222222222222222222222222222222222222222222222",
  ) == None
}
