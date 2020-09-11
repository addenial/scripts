module Windows
  module Security
    module Constants
      private

      TOKEN_QUERY = 8
      ERROR_NO_TOKEN = 1008
      MAXDWORD = 0xFFFFFFFF

      # ACL Revisions

      ACL_REVISION1 = 1
      ACL_REVISION  = 2
      ACL_REVISION2 = 2
      ACL_REVISION3 = 3
      ACL_REVISION4 = 4

      # ACL Information Classes

      AclRevisionInformation = 1
      AclSizeInformation     = 2

      # Identifier Authorities

      SECURITY_NULL_SID_AUTHORITY         = 0
      SECURITY_WORLD_SID_AUTHORITY        = 1
      SECURITY_LOCAL_SID_AUTHORITY        = 2
      SECURITY_CREATOR_SID_AUTHORITY      = 3
      SECURITY_NON_UNIQUE_AUTHORITY       = 4
      SECURITY_NT_AUTHORITY               = 5
      SECURITY_RESOURCE_MANAGER_AUTHORITY = 9

      # Subauthorities

      SECURITY_NULL_RID                 = 0x00000000
      SECURITY_WORLD_RID                = 0x00000000
      SECURITY_LOCAL_RID                = 0x00000000
      SECURITY_CREATOR_OWNER_RID        = 0x00000000
      SECURITY_CREATOR_GROUP_RID        = 0x00000001
      SECURITY_CREATOR_OWNER_SERVER_RID = 0x00000002
      SECURITY_CREATOR_GROUP_SERVER_RID = 0x00000003
      SECURITY_DIALUP_RID               = 0x00000001
      SECURITY_NETWORK_RID              = 0x00000002
      SECURITY_BATCH_RID                = 0x00000003
      SECURITY_INTERACTIVE_RID          = 0x00000004
      SECURITY_LOGON_IDS_RID            = 0x00000005
      SECURITY_LOGON_IDS_RID_COUNT      = 3
      SECURITY_SERVICE_RID              = 0x00000006
      SECURITY_ANONYMOUS_LOGON_RID      = 0x00000007
      SECURITY_PROXY_RID                = 0x00000008

      SECURITY_ENTERPRISE_CONTROLLERS_RID   = 0x00000009
      SECURITY_SERVER_LOGON_RID             = SECURITY_ENTERPRISE_CONTROLLERS_RID
      SECURITY_PRINCIPAL_SELF_RID           = 0x0000000A
      SECURITY_AUTHENTICATED_USER_RID       = 0x0000000B
      SECURITY_RESTRICTED_CODE_RID          = 0x0000000C
      SECURITY_TERMINAL_SERVER_RID          = 0x0000000D
      SECURITY_REMOTE_LOGON_RID             = 0x0000000E
      SECURITY_THIS_ORGANIZATION_RID        = 0x0000000F
      SECURITY_LOCAL_SYSTEM_RID             = 0x00000012
      SECURITY_LOCAL_SERVICE_RID            = 0x00000013
      SECURITY_NETWORK_SERVICE_RID          = 0x00000014
      SECURITY_NT_NON_UNIQUE                = 0x00000015
      SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT = 3

      SECURITY_BUILTIN_DOMAIN_RID     = 0x00000020
      SECURITY_PACKAGE_BASE_RID       = 0x00000040
      SECURITY_PACKAGE_RID_COUNT      = 2
      SECURITY_PACKAGE_NTLM_RID       = 0x0000000A
      SECURITY_PACKAGE_SCHANNEL_RID   = 0x0000000E
      SECURITY_PACKAGE_DIGEST_RID     = 0x00000015
      SECURITY_MAX_ALWAYS_FILTERED    = 0x000003E7
      SECURITY_MIN_NEVER_FILTERED     = 0x000003E8

      SECURITY_OTHER_ORGANIZATION_RID     = 0x000003E8
      FOREST_USER_RID_MAX                 = 0x000001F3
      DOMAIN_USER_RID_ADMIN               = 0x000001F4
      DOMAIN_USER_RID_GUEST               = 0x000001F5
      DOMAIN_USER_RID_KRBTGT              = 0x000001F6
      DOMAIN_USER_RID_MAX                 = 0x000003E7
      DOMAIN_GROUP_RID_ADMINS             = 0x00000200
      DOMAIN_GROUP_RID_USERS              = 0x00000201
      DOMAIN_GROUP_RID_GUESTS             = 0x00000202
      DOMAIN_GROUP_RID_COMPUTERS          = 0x00000203
      DOMAIN_GROUP_RID_CONTROLLERS        = 0x00000204
      DOMAIN_GROUP_RID_CERT_ADMINS        = 0x00000205
      DOMAIN_GROUP_RID_SCHEMA_ADMINS      = 0x00000206
      DOMAIN_GROUP_RID_ENTERPRISE_ADMINS  = 0x00000207
      DOMAIN_GROUP_RID_POLICY_ADMINS      = 0x00000208
      DOMAIN_ALIAS_RID_ADMINS             = 0x00000220
      DOMAIN_ALIAS_RID_USERS              = 0x00000221
      DOMAIN_ALIAS_RID_GUESTS             = 0x00000222
      DOMAIN_ALIAS_RID_POWER_USERS        = 0x00000223
      DOMAIN_ALIAS_RID_ACCOUNT_OPS        = 0x00000224
      DOMAIN_ALIAS_RID_SYSTEM_OPS         = 0x00000225
      DOMAIN_ALIAS_RID_PRINT_OPS          = 0x00000226
      DOMAIN_ALIAS_RID_BACKUP_OPS         = 0x00000227
      DOMAIN_ALIAS_RID_REPLICATOR         = 0x00000228
      DOMAIN_ALIAS_RID_RAS_SERVERS        = 0x00000229

      DOMAIN_ALIAS_RID_PREW2KCOMPACCESS               = 0x0000022A
      DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS           = 0x0000022B
      DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS      = 0x0000022C
      DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS = 0x0000022D
      DOMAIN_ALIAS_RID_MONITORING_USERS               = 0x0000022E
      DOMAIN_ALIAS_RID_LOGGING_USERS                  = 0x0000022F
      DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS            = 0x00000230
      DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS             = 0x00000231
      DOMAIN_ALIAS_RID_DCOM_USERS                     = 0x00000232

      # SID types

      SidTypeUser           = 1
      SidTypeGroup          = 2
      SidTypeDomain         = 3
      SidTypeAlias          = 4
      SidTypeWellKnownGroup = 5
      SidTypeDeletedAccount = 6
      SidTypeInvalid        = 7
      SidTypeUnknown        = 8
      SidTypeComputer       = 9

      # SDDL version information

      SDDL_REVISION_1 = 1

      # ACE flags

      OBJECT_INHERIT_ACE                      = 0x1
      CONTAINER_INHERIT_ACE                   = 0x2
      NO_PROPAGATE_INHERIT_ACE                = 0x4
      INHERIT_ONLY_ACE                        = 0x8
      INHERITED_ACE                           = 0x10

      # ACE Types

      ACCESS_MIN_MS_ACE_TYPE                  = 0x0
      ACCESS_ALLOWED_ACE_TYPE                 = 0x0
      ACCESS_DENIED_ACE_TYPE                  = 0x1
      SYSTEM_AUDIT_ACE_TYPE                   = 0x2
      SYSTEM_ALARM_ACE_TYPE                   = 0x3
      ACCESS_MAX_MS_V2_ACE_TYPE               = 0x3
      ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 0x4
      ACCESS_MAX_MS_V3_ACE_TYPE               = 0x4
      ACCESS_MIN_MS_OBJECT_ACE_TYPE           = 0x5
      ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x5
      ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x6
      SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 0x7
      SYSTEM_ALARM_OBJECT_ACE_TYPE            = 0x8
      ACCESS_MAX_MS_OBJECT_ACE_TYPE           = 0x8
      ACCESS_MAX_MS_V4_ACE_TYPE               = 0x8
      ACCESS_MAX_MS_ACE_TYPE                  = 0x8
      ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x9
      ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0xA
      ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB
      ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0xC
      SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 0xD
      SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 0xE
      SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 0xF
      SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 0x10
      ACCESS_MAX_MS_V5_ACE_TYPE               = 0x10

      # Standard Access Rights

      DELETE                       = 0x00010000
      READ_CONTROL                 = 0x20000
      WRITE_DAC                    = 0x40000
      WRITE_OWNER                  = 0x80000
      SYNCHRONIZE                  = 0x100000
      STANDARD_RIGHTS_REQUIRED     = 0xf0000
      STANDARD_RIGHTS_READ         = 0x20000
      STANDARD_RIGHTS_WRITE        = 0x20000
      STANDARD_RIGHTS_EXECUTE      = 0x20000
      STANDARD_RIGHTS_ALL          = 0x1F0000
      SPECIFIC_RIGHTS_ALL          = 0xFFFF
      ACCESS_SYSTEM_SECURITY       = 0x1000000
      MAXIMUM_ALLOWED              = 0x2000000
      GENERIC_READ                 = 0x80000000
      GENERIC_WRITE                = 0x40000000
      GENERIC_EXECUTE              = 0x20000000
      GENERIC_ALL                  = 0x10000000
    end
  end
end
