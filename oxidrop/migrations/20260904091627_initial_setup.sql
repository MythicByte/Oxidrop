CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    
    -- Roles
    role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin', 'viewer')),

    -- Permissions Bitmask: 
    -- 1 = Create (001)
    -- 2 = Modify (010)
    -- 4 = Delete (100)
    -- Example: 7 (111) = All permissions, 3 (011) = Create and Modify
    action_permissions INTEGER NOT NULL DEFAULT 0 CHECK(action_permissions BETWEEN 0 AND 7),

    -- Password must be changed (0 = no, 1 = yes)
    password_must_be_changed INTEGER NOT NULL DEFAULT 1 CHECK(password_must_be_changed IN (0, 1)),
    
    -- Status: Restricted to 0 or 1 to emulate a strict boolean
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
    
    -- Timestamps: Stored as Integers (Unix Epoch)
    last_login_at INTEGER, 
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE firewall_logs (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL CHECK (timestamp > 0),
    level TEXT NOT NULL CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')),
    message TEXT NOT NULL,
    actor TEXT,
    source_ip TEXT CHECK (source_ip IS NULL OR length(source_ip) BETWEEN 7 AND 45),
    destination_ip TEXT CHECK (destination_ip IS NULL OR length(destination_ip) BETWEEN 7 AND 45),
    source_port INTEGER CHECK (source_port IS NULL OR (source_port >= 0 AND source_port <= 65535)),
    destination_port INTEGER CHECK (destination_port IS NULL OR (destination_port >= 0 AND destination_port <= 65535)),
    protocol TEXT CHECK (protocol IS NULL OR protocol IN ('TCP', 'UDP', 'ICMP', 'IGMP', 'GRE', 'IPv6-ICMP')),
    action TEXT CHECK (action IS NULL OR action IN ('ALLOW', 'DENY', 'DROP', 'REJECT'))
) STRICT;

CREATE INDEX idx_firewall_logs_timestamp ON firewall_logs(timestamp DESC);

CREATE TABLE firewall_config (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    
    -- TCP Profile
    tcp_rate_shift INTEGER NOT NULL,
    tcp_burst INTEGER NOT NULL,
    
    -- UDP Profile
    udp_rate_shift INTEGER NOT NULL,
    udp_burst INTEGER NOT NULL,
    
    -- ICMP Profile
    icmp_rate_shift INTEGER NOT NULL,
    icmp_burst INTEGER NOT NULL,
    
    -- Default Profile
    default_rate_shift INTEGER NOT NULL,
    default_burst INTEGER NOT NULL,
    
    -- Bitflags for allowed protocols (ActivaterEtherTypes)
    protocol_allowed INTEGER NOT NULL,
    
    -- DDoS Protection Toggle: Restricted to boolean
    ddos_activated INTEGER NOT NULL CHECK(ddos_activated IN (0, 1)),
     
    -- Whether subnet matching is enforced
    subnet_activated INTEGER NOT NULL DEFAULT 1 CHECK(subnet_activated IN (0, 1)),
    
    -- Ethernet Adapters (Optional, so they can be NULL)
    incoming_ethernet_adapter INTEGER,
    output_ethernet_adapter INTEGER
);

-- IPv4 Subnet Matching
CREATE TABLE subnet_match_v4 (
    network INTEGER NOT NULL,     -- u32 representation
    prefix_len INTEGER NOT NULL CHECK(prefix_len BETWEEN 0 AND 32),
    -- Actions strictly mapped to enum: Allow = 0, Deny = 1
    action INTEGER NOT NULL CHECK(action IN (0, 1)),
    PRIMARY KEY (network, prefix_len)
);

-- IPv6 Subnet Matching
CREATE TABLE subnet_match_v6 (
    -- Force 16 bytes representing [u32; 4]
    network BLOB NOT NULL CHECK(length(network) = 16), 
    prefix_len INTEGER NOT NULL CHECK(prefix_len BETWEEN 0 AND 128),
    -- Actions strictly mapped to enum: Allow = 0, Deny = 1
    action INTEGER NOT NULL CHECK(action IN (0, 1)),
    PRIMARY KEY (network, prefix_len)
);

-- IPv4 Allow List
CREATE TABLE allow_list_v4 (
    id INTEGER PRIMARY KEY,
    source_addr INTEGER NOT NULL,
    destination_addr INTEGER NOT NULL,
    -- Strictly clamp ports to u16 bounds
    source_port INTEGER NOT NULL CHECK(source_port BETWEEN 0 AND 65535),
    destination_port INTEGER NOT NULL CHECK(destination_port BETWEEN 0 AND 65535),
    -- Strictly clamp protocol to u8 bounds
    protocol INTEGER NOT NULL CHECK(protocol BETWEEN 0 AND 255),
    
    -- AllowListState Data
    action INTEGER NOT NULL CHECK(action IN (0, 1)),
    last_seen INTEGER NOT NULL,
    
    UNIQUE(source_addr, destination_addr, source_port, destination_port, protocol)
);

-- IPv6 Allow List
CREATE TABLE allow_list_v6 (
    id INTEGER PRIMARY KEY,
    -- Force 16 bytes ([u32; 4])
    source_addr BLOB NOT NULL CHECK(length(source_addr) = 16),
    destination_addr BLOB NOT NULL CHECK(length(destination_addr) = 16),
    -- Strictly clamp ports to u16 bounds
    source_port INTEGER NOT NULL CHECK(source_port BETWEEN 0 AND 65535),
    destination_port INTEGER NOT NULL CHECK(destination_port BETWEEN 0 AND 65535),
    -- Strictly clamp protocol to u8 bounds
    protocol INTEGER NOT NULL CHECK(protocol BETWEEN 0 AND 255),
    
    -- AllowListState Data
    action INTEGER NOT NULL CHECK(action IN (0, 1)),
    last_seen INTEGER NOT NULL,
    
    UNIQUE(source_addr, destination_addr, source_port, destination_port, protocol)
);

-- IPv4 Packet Counts
CREATE TABLE packet_counts_v4 (
    id INTEGER PRIMARY KEY,
    source_addr INTEGER NOT NULL,
    destination_addr INTEGER NOT NULL,
    -- Strictly clamp ports to u16 bounds
    source_port INTEGER NOT NULL CHECK(source_port BETWEEN 0 AND 65535),
    destination_port INTEGER NOT NULL CHECK(destination_port BETWEEN 0 AND 65535),
    -- Strictly clamp protocol to u8 bounds
    protocol INTEGER NOT NULL CHECK(protocol BETWEEN 0 AND 255),
    
    -- TokenBucketState Data
    tokens INTEGER NOT NULL,
    last_update INTEGER NOT NULL,
    
    UNIQUE(source_addr, destination_addr, source_port, destination_port, protocol)
);

-- IPv6 Packet Counts
CREATE TABLE packet_counts_v6 (
    id INTEGER PRIMARY KEY,
    -- Force 16 bytes ([u32; 4])
    source_addr BLOB NOT NULL CHECK(length(source_addr) = 16),       
    destination_addr BLOB NOT NULL CHECK(length(destination_addr) = 16),
    -- Strictly clamp ports to u16 bounds
    source_port INTEGER NOT NULL CHECK(source_port BETWEEN 0 AND 65535),
    destination_port INTEGER NOT NULL CHECK(destination_port BETWEEN 0 AND 65535),
    -- Strictly clamp protocol to u8 bounds
    protocol INTEGER NOT NULL CHECK(protocol BETWEEN 0 AND 255),
    
    -- TokenBucketState Data
    tokens INTEGER NOT NULL,
    last_update INTEGER NOT NULL,
    
    UNIQUE(source_addr, destination_addr, source_port, destination_port, protocol)
);
