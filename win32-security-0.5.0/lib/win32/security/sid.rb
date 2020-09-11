require 'socket'

# The Win32 module serves as a namespace only.
module Win32

  # The Security class serves as a toplevel class namespace.
  class Security

    # The SID class encapsulates a Security Identifier.
    class SID
      include Windows::Security::Constants
      include Windows::Security::Functions
      include Windows::Security::Structs
      extend Windows::Security::Functions

      # The version of the Win32::Security::SID class.
      VERSION = '0.2.5'

      # Some constant SID's for your convenience, in string format.
      # See http://support.microsoft.com/kb/243330 for details.

      Null                        = 'S-1-0'
      Nobody                      = 'S-1-0-0'
      World                       = 'S-1-1'
      Everyone                    = 'S-1-1-0'
      Local                       = 'S-1-2'
      Creator                     = 'S-1-3'
      CreatorOwner                = 'S-1-3-0'
      CreatorGroup                = 'S-1-3-1'
      CreatorOwnerServer          = 'S-1-3-2'
      CreatorGroupServer          = 'S-1-3-3'
      NonUnique                   = 'S-1-4'
      Nt                          = 'S-1-5'
      Dialup                      = 'S-1-5-1'
      Network                     = 'S-1-5-2'
      Batch                       = 'S-1-5-3'
      Interactive                 = 'S-1-5-4'
      Service                     = 'S-1-5-6'
      Anonymous                   = 'S-1-5-7'
      Proxy                       = 'S-1-5-8'
      EnterpriseDomainControllers = 'S-1-5-9'
      PrincipalSelf               = 'S-1-5-10'
      AuthenticatedUsers          = 'S-1-5-11'
      RestrictedCode              = 'S-1-5-12'
      TerminalServerUsers         = 'S-1-5-13'
      LocalSystem                 = 'S-1-5-18'
      NtLocal                     = 'S-1-5-19'
      NtNetwork                   = 'S-1-5-20'
      BuiltinAdministrators       = 'S-1-5-32-544'
      BuiltinUsers                = 'S-1-5-32-545'
      Guests                      = 'S-1-5-32-546'
      PowerUsers                  = 'S-1-5-32-547'
      AccountOperators            = 'S-1-5-32-548'
      ServerOperators             = 'S-1-5-32-549'
      PrintOperators              = 'S-1-5-32-550'
      BackupOperators             = 'S-1-5-32-551'
      Replicators                 = 'S-1-5-32-552'

      # The binary SID object itself.
      attr_reader :sid

      # The account name passed to the constructor.
      attr_reader :account

      # The SID account type, e.g. 'user, 'group', etc.
      attr_reader :account_type

      # The domain the SID is on.
      attr_reader :domain

      # The host passed to the constructor, or the localhost if none
      # was specified.
      attr_reader :host

      # Converts a binary SID to a string in S-R-I-S-S... format.
      #
      def self.sid_to_string(sid)
        result = nil

        FFI::MemoryPointer.new(:pointer) do |string_sid|
          unless ConvertSidToStringSid(sid, string_sid)
            FFI.raise_windows_error('ConvertSidToStringSid')
          end

          result = string_sid.read_pointer.read_string
        end

        result
      end

      # Converts a string in S-R-I-S-S... format back to a binary SID.
      #
      def self.string_to_sid(string)
        result = nil

        FFI::MemoryPointer.new(:pointer) do |sid|
          unless ConvertStringSidToSid(string, sid)
            FFI.raise_windows_error('ConvertStringSidToSid')
          end

          ptr = sid.read_pointer

          result = ptr.read_bytes(GetLengthSid(ptr))
        end

        result
      end

      # Creates a new SID with +authority+ and up to 8 +subauthorities+,
      # and returns new Win32::Security::SID object.
      #
      # Example:
      #
      #    sec = Security::SID.create(
      #       Security::SID::SECURITY_WORLD_SID_AUTHORITY,
      #       Security::SID::SECURITY_WORLD_RID
      #    )
      #
      #    p sec
      #
      #    #<Win32::Security::SID:0x2c5a95c
      #       @host="your_host",
      #       @account="Everyone",
      #       @account_type="well known group",
      #       @sid="\001\001\000\000\000\000\000\001\000\000\000\000",
      #       @domain=""
      #    >
      #
      def self.create(authority, *sub_authorities)
        if sub_authorities.length > 8
          raise ArgumentError, "maximum of 8 subauthorities allowed"
        end

        size = GetSidLengthRequired(sub_authorities.length)
        new_obj = nil

        FFI::MemoryPointer.new(:uchar, size) do |sid|
          auth = SID_IDENTIFIER_AUTHORITY.new
          auth[:Value][5] = authority

          unless InitializeSid(sid, auth, sub_authorities.length)
            FFI.raise_windows_error('InitializeSid')
          end

          sub_authorities.each_index do |i|
            ptr = GetSidSubAuthority(sid, i)
            ptr.write_ulong(sub_authorities[i])
          end

          new_obj = new(sid.read_string(size)) # Pass a binary string
        end

        new_obj
      end

      # Creates and returns a new Win32::Security::SID object, based on
      # the account name, which may also be a binary SID. If a host is
      # provided, then the information is retrieved from that host.
      # Otherwise, the local host is used.
      #
      # If no account is provided then it retrieves information for the
      # user account associated with the calling thread and the host argument
      # is ignored.
      #
      # Note that this does NOT create a new SID, but merely retrieves
      # information for an existing SID. To create a new SID, use the
      # SID.create method.
      #
      # Examples:
      #
      #  # Current user
      #  Win32::Security::SID.new
      #
      #  # User 'john' on the localhost
      #  Win32::Security::SID.new('john')
      #
      #  # User 'jane' on a remote machine
      #  Win32::Security::SID.new('jane', 'some_host')
      #
      #  # Binary SID
      #  Win32::Security::SID.new("\001\000\000\000\000\000\001\000\000\000\000")
      #
      def initialize(account=nil, host=Socket.gethostname)
        if account.nil?
          begin
            if RUBY_PLATFORM == 'java' && ENV_JAVA['sun.arch.data.model'] == '64'
              ptr_type = :ulong_long
            else
              ptr_type = :uintptr_t
            end

            ptoken = FFI::MemoryPointer.new(ptr_type)

            # Try the thread token first, default to the process token.
            bool = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, ptoken)

            unless bool
              ptoken.clear
              unless OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ptoken)
                FFI.raise_windows_error('OpenProcessToken')
              end
            end

            token = ptoken.read_pointer.to_i

            pinfo = FFI::MemoryPointer.new(:pointer)
            plength = FFI::MemoryPointer.new(:ulong)

            # First pass, just get the size needed (1 is TokenOwner)
            GetTokenInformation(token, 1, pinfo, pinfo.size, plength)

            pinfo = FFI::MemoryPointer.new(plength.read_ulong)
            plength.clear

            # Second pass, actual call (1 is TokenOwner)
            unless GetTokenInformation(token, 1, pinfo, pinfo.size, plength)
              FFI.raise_windows_error('GetTokenInformation')
            end

            token_info = pinfo.read_pointer
          ensure
            CloseHandle(token) if token
          end
        end

        ordinal_val = account ? account[0].ord : nil

        sid = FFI::MemoryPointer.new(:uchar, 1024)
        sid_size = FFI::MemoryPointer.new(:ulong)
        sid_size.write_ulong(sid.size)

        domain = FFI::MemoryPointer.new(:uchar, 1024)
        domain_size = FFI::MemoryPointer.new(:ulong)
        domain_size.write_ulong(domain.size)

        use_ptr = FFI::MemoryPointer.new(:ulong)

        if ordinal_val.nil?
          bool = LookupAccountSid(
            nil,
            token_info,
            sid,
            sid_size,
            domain,
            domain_size,
            use_ptr
          )
          unless bool
            FFI.raise_windows_error('LookupAccountSid')
          end
        elsif ordinal_val < 10 # Assume it's a binary SID.
          account_ptr = FFI::MemoryPointer.from_string(account)

          bool = LookupAccountSid(
            host.wincode,
            account_ptr,
            sid,
            sid_size,
            domain,
            domain_size,
            use_ptr
          )

          unless bool
            FFI.raise_windows_error('LookupAccountSid')
          end

          account_ptr.free
        else
          bool = LookupAccountName(
            host.wincode,
            account.wincode,
            sid,
            sid_size,
            domain,
            domain_size,
            use_ptr
          )
          unless bool
            FFI.raise_windows_error('LookupAccountName')
          end
        end

        # The arguments are flipped depending on which path we took
        if ordinal_val.nil?
          length = GetLengthSid(token_info)
          @sid = token_info.read_string(length)
          @account = sid.read_bytes(sid.size).wstrip
        elsif ordinal_val < 10
          @sid = account
          @account = sid.read_bytes(sid.size).wstrip
        else
          length = GetLengthSid(sid)
          @sid = sid.read_bytes(length)
          @account = account
        end


        @host   = host
        @domain = domain.read_bytes(domain.size).wstrip

        @account_type = get_account_type(use_ptr.read_ulong)
      end

      # Synonym for SID.new.
      #
      def self.open(account=nil, host=Socket.gethostname)
        new(account, host)
      end

      # Returns the binary SID in string format suitable for display,
      # storage or transmission.
      #
      def to_s
        string = nil

        FFI::MemoryPointer.new(:pointer) do |ptr|
          unless ConvertSidToStringSid(@sid, ptr)
            FFI.raise_windows_error('ConvertSidToStringSid')
          end

          string = ptr.read_pointer.read_string
        end

        string
      end

      alias to_str to_s

      # Returns whether or not the SID object is equal to +other+.
      #
      def ==(other)
        EqualSid(@sid, other.sid)
      end

      # Returns whether or not the SID is a valid sid.
      #
      def valid?
        IsValidSid(@sid)
      end

      # Returns whether or not the SID is a well known SID.
      #
      # Requires Windows XP or later. Earlier versions will raise a
      # NoMethodError.
      #
      def well_known?
        if defined? IsWellKnownSid
          IsWellKnownSid(@sid)
        else
          raise NoMethodError, 'requires Windows XP or later'
        end
      end

      # Returns the length of the SID object, in bytes.
      #
      def length
        GetLengthSid(@sid)
      end

      private

      # Converts a numeric account type into a human readable string.
      #
      def get_account_type(value)
        case value
          when SidTypeUser
            'user'
          when SidTypeGroup
            'group'
          when SidTypeDomain
            'domain'
          when SidTypeAlias
            'alias'
          when SidTypeWellKnownGroup
            'well known group'
          when SidTypeDeletedAccount
            'deleted account'
          when SidTypeInvalid
            'invalid'
          when SidTypeUnknown
            'unknown'
          when SidComputer
            'computer'
        end
      end
    end
  end
end
