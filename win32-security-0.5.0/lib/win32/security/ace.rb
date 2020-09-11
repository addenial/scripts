# The Win32 module serves as a namespace only.
module Win32

  # The Security class serves as a toplevel class namespace.
  class Security

    # The ACE class encapsulates an Access Control Entry, an element within
    # an Access Control List.
    class ACE
      # The version of the Win32::Security::ACE class.
      VERSION = '0.1.0'

      # The ACE type, e.g. ACCESS_ALLOWED, ACCESS_DENIED, etc. This is an integer.
      attr_accessor :ace_type

      # Standard access rights, e.g. GENERIC_READ, GENERIC_WRITE, etc.
      # This is an integer.
      attr_accessor :access_mask

      # Bit flags associated with the ACE, e.g. OBJECT_INHERIT_ACE, etc.
      # This is an integer.
      attr_reader :flags

      # Creates and returns an ACE object.
      #
      def initialize(access_mask, ace_type, flags)
        @access_mask = access_mask
        @ace_type = ace_type
        @flags = flags
        yield self if block_given?
      end

      # Returns the type of ace as a string, e.g. "ACCESS_ALLOWED_TYPE_ACE".
      #
      def ace_type_string
        case @ace_type
          when 0x0
            'ACCESS_ALLOWED_ACE_TYPE'
          when 0x1
            'ACCESS_DENIED_ACE_TYPE'
          when 0x2
            'SYSTEM_AUDIT_ACE_TYPE'
          when 0x3
            'SYSTEM_ALARM_ACE_TYPE'
          when 0x4
            'ACCESS_ALLOWED_COMPOUND_ACE_TYPE'
          when 0x5
            'ACCESS_ALLOWED_OBJECT_ACE_TYPE'
          when 0x6
            'ACCESS_DENIED_OBJECT_ACE_TYPE'
          when 0x7
            'SYSTEM_AUDIT_OBJECT_ACE_TYPE'
          when 0x8
            'SYSTEM_ALARM_OBJECT_ACE_TYPE'
          when 0x9
            'ACCESS_ALLOWED_CALLBACK_ACE_TYPE'
          when 0xA
            'ACCESS_DENIED_CALLBACK_ACE_TYPE'
          when 0xB
            'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE'
          when 0xC
            'ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE'
          when 0xD
            'SYSTEM_AUDIT_CALLBACK_ACE_TYPE'
          when 0xE
            'SYSTEM_ALARM_CALLBACK_ACE_TYPE'
          when 0xF
            'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE'
          when 0x10
            'SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE'
        end
      end
    end
  end
end
