# This file allows users to require all security related classes from
# a single file, instead of having to require individual files.

#require 'ffi/win32/extensions'
require './ffi-win32-extensions-1.0.4/lib/ffi/win32/extensions'
require_relative 'security/windows/constants'
require_relative 'security/windows/structs'
require_relative 'security/windows/functions'

# The Win32 module serves as a namespace only.
module Win32

  # The Security class encapsulates security aspects of MS Windows.
  class Security

    # Base error class for all Win32::Security errors.
    class Error < StandardError; end

    include Windows::Security::Functions
    include Windows::Security::Constants
    include Windows::Security::Structs
    extend Windows::Security::Functions

    # The version of the win32-security library
    VERSION = '0.5.0'

    # Used by OpenProcessToken
    TOKEN_QUERY = 8

    # Returns whether or not the owner of the current process is running
    # with elevated security privileges.
    #
    def self.elevated_security?
      result = false

      # Work around a 64-bit JRuby bug
      if RUBY_PLATFORM == 'java' && ENV_JAVA['sun.arch.data.model'] == '64'
        ptr_type = :ulong_long
      else
        ptr_type = :uintptr_t
      end

      FFI::MemoryPointer.new(ptr_type) do |token|
        unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token)
          FFI.raise_windows_error('OpenProcessToken')
        end

        begin
          token = token.read_pointer.to_i

          # Since the TokenElevation struct only has 1 member, we use a pointer.
          te = FFI::MemoryPointer.new(:pointer)
          rl = FFI::MemoryPointer.new(:ulong)

          bool = GetTokenInformation(
            token,
            :TokenElevation,
            te,
            te.size,
            rl
          )

          te.free
          te = FFI::MemoryPointer.new(rl.read_ulong)
          rl.clear

          bool = GetTokenInformation(
            token,
            :TokenElevation,
            te,
            te.size,
            rl
          )

          FFI.raise_windows_error('GetTokenInformation') unless bool

          token_info = rl.read_ulong == 4 ? te.read_uint : te.read_ulong
          result = token_info != 0
        ensure
          CloseHandle(token)
          te.free
          rl.free
        end
      end

      result
    end

    private

    def self.windows_version
      ver = OSVERSIONINFO.new
      ver[:dwOSVersionInfoSize] = ver.size

      unless GetVersionExA(ver)
        FFI.raise_windows_error('GetVersionEx')
      end

      ver[:dwMajorVersion]
    end
  end
end


require './win32-security-0.5.0/lib/win32/security/sid.rb'
require './win32-security-0.5.0/lib/win32/security/acl'
require './win32-security-0.5.0/lib/win32/security/ace'
#require 'win32/security/sid'
#require 'win32/security/acl'
#require 'win32/security/ace'
