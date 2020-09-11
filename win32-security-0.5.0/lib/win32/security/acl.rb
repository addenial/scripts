# The Win32 module serves as a namespace only.
module Win32

  # The Security class serves as a toplevel class namespace.
  class Security

    # The ACL class encapsulates an Access Control List.
    class ACL
      include Windows::Security::Constants
      include Windows::Security::Functions
      include Windows::Security::Structs
      extend Windows::Security::Functions

      # The version of the Win32::Security::ACL class.
      VERSION = '0.2.1'

      # The underlying ACL structure.
      attr_reader :acl

      # The revision level.
      attr_reader :revision

      # Creates and returns a new Win32::Security::ACL object. This object
      # encapsulates an ACL structure, including a binary representation of
      # the ACL itself, and the revision information.
      #
      def initialize(size = 1024, revision = ACL_REVISION)
        acl = ACL_STRUCT.new

        unless InitializeAcl(acl, size, revision)
          FFI.raise_windows_error('InitializeAcl')
        end

        @acl = acl
        @revision = revision
      end

      # Returns the number of ACE's in the ACL object.
      #
      def ace_count
        info = ACL_SIZE_INFORMATION.new

        unless GetAclInformation(@acl, info, info.size, AclSizeInformation)
          FFI.raise_windows_error('GetAclInformation')
        end

        info[:AceCount]
      end

      # Returns a two element array that consists of the bytes in use and
      # bytes free for the ACL.
      #
      def byte_info
        info = ACL_SIZE_INFORMATION.new

        unless GetAclInformation(@acl, info, info.size, AclSizeInformation)
          FFI.raise_windows_error('GetAclInformation')
        end

        [info[:AclBytesInUse], info[:AclBytesFree]]
      end

      # Adds an access allowed ACE to the given +sid+, which can be a
      # Win32::Security::SID object or a plain user or group name. If no
      # sid is provided then the owner of the current process is used.
      #
      # The +mask+ is a bitwise OR'd value of access rights.
      #
      # The +flags+ argument can be anyone of the following constants.
      #
      # * OBJECT_INHERIT_ACE
      # * CONTAINER_INHERIT_ACE
      # * NO_PROPAGATE_INHERIT_ACE
      # * INHERIT_ONLY_ACE
      # * INHERITED_ACE
      #
      # Example:
      #
      #   acl = Win32::Security::ACL.new
      #   acl.add_access_allowed_ace('some_user', GENERIC_READ | GENERIC_WRITE)
      #
      def add_access_allowed_ace(sid=nil, mask=0, flags=nil)
        if sid.is_a?(Win32::Security::SID)
          sid = sid.sid
        else
          sid = Win32::Security::SID.new(sid).sid
        end

        if flags
          unless AddAccessAllowedAceEx(@acl, @revision, flags, mask, sid)
            FFI.raise_windows_error('AddAccessAllowedAceEx')
          end
        else
          unless AddAccessAllowedAce(@acl, @revision, mask, sid)
            FFI.raise_windows_error('AddAccessAllowedAce')
          end
        end

        sid
      end

      # Adds an access denied ACE to the given +sid+, which can be a
      # Win32::Security::SID object ora plain user or group name. If
      # no sid is provided then the owner of the current process is used.
      #
      # The +mask+ is the bitwise OR'd value of access rights.
      #
      # The +flags+ argument can be any one of the following constants:
      #
      # * OBJECT_INHERIT_ACE
      # * CONTAINER_INHERIT_ACE
      # * NO_PROPAGATE_INHERIT_ACE
      # * INHERIT_ONLY_ACE
      # * INHERITED_ACE
      #
      def add_access_denied_ace(sid=nil, mask=0, flags=nil)
        if sid.is_a?(Win32::Security::SID)
          sid = sid.sid
        else
          sid = Win32::Security::SID.new(sid).sid
        end

        if flags
          unless AddAccessDeniedAceEx(@acl, @revision, flags, mask, sid)
            FFI.raise_windows_error('AddAccessDeniedAceEx')
          end
        else
          unless AddAccessDeniedAce(@acl, @revision, mask, sid)
            FFI.raise_windows_error('AddAccessDeniedAce')
          end
        end
      end

      # Adds an ACE to the ACL object with the given +revision+ at +index+
      # or the end of the chain if no index is specified.
      #
      # Returns the index if successful.
      #--
      # This won't work until we implement the ACE class.
      #
      def add_ace(ace, index=MAXDWORD)
        unless AddAce(@acl, @revision, index, ace, ace.length)
          FFI.raise_windows_error('AddAce')
        end

        index
      end

      # Deletes an ACE from the ACL object at +index+, or from the end of
      # the chain if no index is specified.
      #
      # Returns the index if successful.
      #
      def delete_ace(index=MAXDWORD)
        unless DeleteAce(@acl, index)
          FFI.raise_windows_error('DeleteAce')
        end

        index
      end

      # Finds and returns an ACE object for the ACL at the given
      # +index+. If no index is provided, then it returns an ACE object
      # that corresponds to the first free byte of the ACL.
      #
      # If +raw+ is true, it will return an ACCESS_GENERIC_ACE struct,
      # an FFI object that you can then access directly.
      #
      def find_ace(index = nil, raw = false)
        result = nil

        FFI::MemoryPointer.new(:pointer) do |pptr|
          if index.nil?
            unless FindFirstFreeAce(@acl, pptr)
              FFI.raise_windows_error('FindFirstFreeAce')
            end
          else
            unless GetAce(@acl, index, pptr)
              FFI.raise_windows_error('GetAce')
            end
          end

          # There's no way to know what type of ACE it is at this point as far
          # as I know, so we use a generic struct and use the AceType to figure
          # it out later, or the users can.
          ace = ACCESS_GENERIC_ACE.new(pptr.read_pointer)

          if raw
            result = ace
          else
            result = ACE.new(ace[:Mask], ace[:Header][:AceType], ace[:Header][:AceFlags])
          end
        end

        result
      end

      # Sets the revision information level, where the +revision_level+
      # can be ACL_REVISION1, ACL_REVISION2, ACL_REVISION3 or ACL_REVISION4.
      #
      # Returns the revision level if successful.
      #
      def revision=(revision_level)
        FFI::MemoryPointer.new(:ulong) do |buf|
          buf.write_ulong(revision_level)

          unless SetAclInformation(@acl, buf, buf.size, AclRevisionInformation)
            FFI.raise_windows_error('SetAclInformation')
          end
        end

        @revision = revision_level

        revision_level
      end

      # Returns whether or not the ACL is a valid ACL.
      #
      def valid?
        IsValidAcl(@acl)
      end
    end
  end
end
