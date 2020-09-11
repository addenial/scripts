require "ffi" unless defined?(FFI)

class FFI::Pointer
  # Returns an array of strings for char** types.
  #
  def read_array_of_string
    elements = []

    loc = self

    until (element = loc.read_pointer).null?
      elements << element.read_string
      loc += FFI::Type::POINTER.size
    end

    elements
  end

  # Read +num_bytes+ from a wide character string pointer.
  # If this fails (typically because there are only null characters)
  # then an empty string is returned instead.
  #
  def read_wide_string(num_bytes = size)
    read_bytes(num_bytes).force_encoding("UTF-16LE")
      .encode("UTF-8", invalid: :replace, undef: :replace)
      .split(0.chr).first.force_encoding(Encoding.default_external)
  rescue
    ""
  end

  # Read null-terminated Unicode strings.
  #
  def read_wstring(num_wchars = nil)
    if num_wchars.nil?
      # Find the length of the string
      length = 0
      last_char = nil
      while last_char != "\000\000"
        length += 1
        last_char = get_bytes(0, length * 2)[-2..-1]
      end

      num_wchars = length
    end

    wide_to_utf8(get_bytes(0, num_wchars * 2))
  end

  def wide_to_utf8(wstring)
    # ensure it is actually UTF-16LE
    # Ruby likes to mark binary data as ASCII-8BIT
    wstring = wstring.force_encoding("UTF-16LE")

    # encode it all as UTF-8 and remove trailing CRLF and NULL characters
    wstring.encode("UTF-8").strip
  end

  def read_utf16string
    offset = 0
    offset += 2 while get_bytes(offset, 2) != "\x00\x00"
    get_bytes(0, offset).force_encoding("utf-16le").encode("utf-8")
  end
end

module FFI
  extend FFI::Library

  ffi_lib :kernel32

  # We deliberately use the ANSI version because all Ruby error messages are English.
  attach_function :FormatMessage, :FormatMessageA,
    %i{ulong pointer ulong ulong pointer ulong pointer}, :ulong

  # Returns a Windows specific error message based on +err+ prepended
  # with the +function+ name. Note that this does not actually raise
  # an error, it only returns the message.
  #
  # The message will always be English regardless of your locale.
  #
  def windows_error_message(function, err = FFI.errno)
    error_message = ""

    # ARGUMENT_ARRAY + SYSTEM + MAX_WIDTH_MASK
    flags = 0x00001000 | 0x00000200 | 0x000000FF

    # 0x0409 = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)
    # We use English for errors because Ruby uses English for errors.

    FFI::MemoryPointer.new(:char, 1024) do |buf|
      length = FormatMessage(flags, nil, err , 0x0409, buf, buf.size, nil)
      error_message = function + ": " + buf.read_string(length).strip
    end

    error_message
  end

  # Raises a Windows specific error using SystemCallError that is based on
  # the +err+ provided, with the message prepended with the +function+ name.
  #
  def raise_windows_error(function, err = FFI.errno)
    raise SystemCallError.new(windows_error_message(function, err), err)
  end

  module_function :windows_error_message
  module_function :raise_windows_error
end

class String
  # Convenience method for converting strings to UTF-16LE for wide character
  # functions that require it.
  #
  def wincode
    (tr(File::SEPARATOR, File::ALT_SEPARATOR) + 0.chr).encode("UTF-16LE")
  end

  # Read a wide character string up until the first double null, and delete
  # any remaining null characters. If this fails (typically because there
  # are only null characters) then nil is returned instead.
  #
  def wstrip
    force_encoding("UTF-16LE").encode("UTF-8", invalid: :replace, undef: :replace)
      .split("\x00")[0].encode(Encoding.default_external)
  rescue
    nil
  end

  # Read a wide character string up until the first double null, and delete
  # any remaining null characters.
  #
  def read_wide_string
    self[/^.*?(?=\x00{2})/].delete(0.chr)
  end
end
