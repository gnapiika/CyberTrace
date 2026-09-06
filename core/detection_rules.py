DETECTION_RULES = {

    "BRUTE_FORCE_SUCCESS": {
        "name": "Possible Brute-Force Attack",
        "severity": "HIGH",
        "description": (
            "Multiple failed authentication attempts were "
            "followed by a successful login."
        ),
    },

    "SUSPICIOUS_DOWNLOAD_EXECUTION": {
        "name": "Suspicious Download Followed by Execution",
        "severity": "HIGH",
        "description": (
            "A downloaded file was followed by a related "
            "process execution event."
        ),
    },

    "SUSPICIOUS_PROCESS_CHAIN": {
        "name": "Suspicious Process Chain",
        "severity": "HIGH",
        "description": (
            "A potentially suspicious parent-child process "
            "relationship was detected."
        ),
    },

    "USB_FILE_TRANSFER": {
        "name": "Possible USB Data Transfer",
        "severity": "HIGH",
        "description": (
            "A removable USB device was connected and file "
            "activity was detected before disconnection."
        ),
    },

    "SUSPICIOUS_NETWORK_ACTIVITY": {
        "name": "Suspicious Network Activity",
        "severity": "MEDIUM",
        "description": (
            "Network activity occurred near another suspicious event."
        ),
    },

    "CREATE_EXECUTE_DELETE": {
        "name": "Create-Execute-Delete Pattern",
        "severity": "MEDIUM",
        "description": (
            "A file was created, executed or accessed, "
            "and subsequently deleted."
        ),
    },

    "MULTI_STAGE_ACTIVITY": {
        "name": "Multi-Stage Suspicious Activity",
        "severity": "CRITICAL",
        "description": (
            "Multiple suspicious activities were correlated "
            "across different evidence sources."
        ),
    },
}