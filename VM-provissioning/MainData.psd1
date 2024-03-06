@{

    ########################################################################################

    AllNodes = @(
        @{  NodeName                    = '*'
            DefaultGatewayIpV4          = '192.168.1.1'
            DefaultGatewayIpV6          = 'fd36:46d4:a1a7:9d18::1'
            DNS1IpV4                    = '192.168.0.200'
            DNS2IpV4                    = '192.168.0.70'
            DNS3IpV4                    = '192.168.1.1'
            DNS4IpV4                    = '8.8.8.8'
            DNS5IpV4                    = '8.8.4.4'
            DNS1IpV6                    = 'fd36:46d4:a1a7:9d18::200'
            DNS2IpV6                    = 'fd36:46d4:a1a7:9d18::70'
            DNS3IpV6                    = 'fd36:46d4:a1a7:9d18::1'
            DNS4IpV6                    = '2001:4860:4860::8888'
            DNS5IpV6                    = '2001:4860:4860::8844'
            TimeZone                    = 'Romance Standard Time'
            NewAdminName                = 'Administrator'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
        },

        #region ---------- Domain Controllers --------------------------------------------------

        @{  NodeName          = 'DC1'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.200/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::200/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'First Domain Controller of the EguibarIT domain'
            Disks             = 'Multiple-Disks'
        },

        @{  NodeName          = 'DC2'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.70/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::70/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Additional Domain Controller of the EguibarIT domain'
            Disks             = 'Multiple-Disks'
        },

        @{  NodeName          = 'DC3'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.130/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::130/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Additional Domain Controller of the EguibarIT domain'
            Disks             = 'Multiple-Disks'
        },

        @{  NodeName          = 'DC4'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.10/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::10/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Additional Domain Controller of the EguibarIT domain'
            Disks             = 'Multiple-Disks'
        },

        @{  NodeName          = 'DC5'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.12/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::12/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'First Domain Controller of the Admin domain'
        },

        @{  NodeName          = 'DC6'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.72/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::72/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Additional Domain Controller of the Admin domain'
        },

        @{  NodeName          = 'DC7'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.132/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::132/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Additional Domain Controller of the Admin domain'
        },

        @{  NodeName          = 'DC8'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.72/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::72/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Additional Domain Controller of the Admin domain'
        },

        @{  NodeName          = 'DC9'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.14/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::14/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'First Domain Controller of the Contoso domain'
        },

        @{  NodeName          = 'DC10'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.74/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::74/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Additional Domain Controller of the Contoso domain'
        },

        @{  NodeName          = 'DC11'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.134/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::134/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Additional Domain Controller of the Contoso domain'
        },

        @{  NodeName          = 'DC12'
            UsedRoles         = @('Default', 'DomainController', 'Server')
            IPv4              = '192.168.0.204/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::204/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Additional Domain Controller of the Contoso domain'
        },

        #endregion

        #region ---------- Infrastructure Servers ----------------------------------------------

        @{  NodeName          = 'Wsus1'
            UsedRoles         = @('Default', 'Server', 'Wsus')
            IPv4              = '192.168.0.220/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::220/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Windows Service Update Server'
        },

        @{  NodeName          = 'Wsus2'
            UsedRoles         = @('Default', 'Server', 'Wsus')
            IPv4              = '192.168.0.30/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::30/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Windows Service Update Server'
        },

        @{  NodeName          = 'Wsus3'
            UsedRoles         = @('Default', 'Server', 'Wsus')
            IPv4              = '192.168.0.150/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::150/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Windows Service Update Server'
        },

        @{  NodeName          = 'Wsus4'
            UsedRoles         = @('Default', 'Server', 'Wsus')
            IPv4              = '192.168.0.90/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::90/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Windows Service Update Server'
        },

        @{  NodeName          = 'Ca1'
            UsedRoles         = @('Default', 'Server', 'Ca')
            IPv4              = '192.168.0.28/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::28/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Certification Authority'
        },

        @{  NodeName          = 'Ca2'
            UsedRoles         = @('Default', 'Server', 'Ca')
            IPv4              = '192.168.0.218/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::218/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Certification Authority'
        },

        @{  NodeName          = 'Ca3'
            UsedRoles         = @('Default', 'Server', 'Ca')
            IPv4              = '192.168.0.88/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::88/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Certification Authority'
        },

        @{  NodeName          = 'Ca4'
            UsedRoles         = @('Default', 'Server', 'Ca')
            IPv4              = '192.168.0.148/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::148/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Certification Authority'
        },

        @{  NodeName          = 'Scom1'
            UsedRoles         = @('Default', 'Server', 'Scom')
            IPv4              = '192.168.0.225/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::225/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'System Center Operations Manager'
        },

        @{  NodeName          = 'Scom2'
            UsedRoles         = @('Default', 'Server', 'Scom')
            IPv4              = '192.168.0.35/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::35/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'System Center Operations Manager'
        },

        @{  NodeName          = 'Sccm1'
            UsedRoles         = @('Default', 'Server', 'Sccm')
            IPv4              = '192.168.0.94/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::94/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'System Center Configuration Manager'
        },

        @{  NodeName          = 'Sccm2'
            UsedRoles         = @('Default', 'Server', 'Sccm')
            IPv4              = '192.168.0.154/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::154/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'System Center Configuration Manager'
        },

        @{  NodeName          = 'Mdt1'
            UsedRoles         = @('Default', 'Server', 'Mdt')
            IPv4              = '192.168.0.31/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::31/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Windows Deployment Services - Ms Deployment Toolkit'
        },

        @{  NodeName          = 'Mdt2'
            UsedRoles         = @('Default', 'Server', 'Mdt')
            IPv4              = '192.168.0.221/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::221/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Windows Deployment Services - Ms Deployment Toolkit'
        },

        @{  NodeName          = 'Wac1'
            UsedRoles         = @('Default', 'Server', 'Wac')
            IPv4              = '192.168.0.33/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::33/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Windows Admin Center'
        },

        @{  NodeName          = 'Wac2'
            UsedRoles         = @('Default', 'Server', 'Wac')
            IPv4              = '192.168.0.223/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::223/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Windows Admin Center'
        },

        @{  NodeName          = 'Dsc1'
            UsedRoles         = @('Default', 'Server', 'DscPullSrv')
            IPv4              = '192.168.0.152/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::152/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Desired State Configuration Pull Server'
        },

        @{  NodeName          = 'Dsc2'
            UsedRoles         = @('Default', 'Server', 'DscPullSrv')
            IPv4              = '192.168.0.92/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::92/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Desired State Configuration Pull Server'
        },

        @{  NodeName          = 'Vmm1'
            UsedRoles         = @('Default', 'Server', 'VMM')
            IPv4              = '192.168.0.96/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::96/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'System Center - Virtual Machine Manager'
        },

        @{  NodeName          = 'Vmm2'
            UsedRoles         = @('Default', 'Server', 'VMM')
            IPv4              = '192.168.0.156/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::156/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'System Center - Virtual Machine Manager'
        },

        @{  NodeName          = 'ADFS1'
            UsedRoles         = @('Default', 'Server', 'ADFS')
            IPv4              = '192.168.0.38/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::38/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'AD Federation Services'
        },

        @{  NodeName          = 'ADFS2'
            UsedRoles         = @('Default', 'Server', 'ADFS')
            IPv4              = '192.168.0.98/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::98/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'AD Federation Services'
        },

        @{  NodeName          = 'ADFS3'
            UsedRoles         = @('Default', 'Server', 'ADFS')
            IPv4              = '192.168.0.158/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::158/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'AD Federation Services'
        },

        @{  NodeName          = 'ADFS4'
            UsedRoles         = @('Default', 'Server', 'ADFS')
            IPv4              = '192.168.0.228/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::228/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'AD Federation Services'
        },

        @{  NodeName          = 'Sql1'
            UsedRoles         = @('Default', 'Server', 'SQL')
            IPv4              = '192.168.0.29/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::29/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'SQL Server'
        },

        @{  NodeName          = 'Sql2'
            UsedRoles         = @('Default', 'Server', 'SQL')
            IPv4              = '192.168.0.89/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::89/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'SQL Server'
        },

        @{  NodeName          = 'Sql3'
            UsedRoles         = @('Default', 'Server', 'SQL')
            IPv4              = '192.168.0.219/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::219/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'SQL Server'
        },

        @{  NodeName          = 'Sql4'
            UsedRoles         = @('Default', 'Server', 'SQL')
            IPv4              = '192.168.0.149/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::149/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'SQL Server'
        },

        #endregion

        #region ---------- Tier0 Servers -------------------------------------------------------

        @{  NodeName          = 'Srv1'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.87/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::87/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Server 1'
        },

        @{  NodeName          = 'Srv2'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.147/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::147/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Server 2'
        },

        @{  NodeName          = 'Srv3'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.27/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::27/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Server 3'
        },

        @{  NodeName          = 'Srv4'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.217/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::217/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Server 4'
        },

        @{  NodeName          = 'Srv5'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.148/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::148/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Server 5'
        },

        @{  NodeName          = 'Srv6'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.88/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::88/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Server 6'
        },

        @{  NodeName          = 'Srv7'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.218/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::218/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 7'
        },

        @{  NodeName          = 'Srv8'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.28/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::28/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 8'
        },

        #endregion

        #region ---------- PAWs ----------------------------------------------------------------

        @{  NodeName          = 'Paw01'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.20/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::20/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Privileged Access Workstation - Tier0'
        },

        @{  NodeName          = 'Paw02'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.80/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::80/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Privileged Access Workstation - Tier0'
        },

        @{  NodeName          = 'Paw03'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.140/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::140/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Privileged Access Workstation - Tier0'
        },

        @{  NodeName          = 'Paw04'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.210/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::210/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Privileged Access Workstation - Tier0'
        },

        @{  NodeName          = 'Paw11'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.212/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::212/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Privileged Access Workstation - Tier1'
        },

        @{  NodeName          = 'Paw12'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.142/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::142/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Privileged Access Workstation - Tier1'
        },

        @{  NodeName          = 'Paw13'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.82/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::82/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Privileged Access Workstation - Tier1'
        },

        @{  NodeName          = 'Paw14'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.22/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::22/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Privileged Access Workstation - Tier1'
        },

        @{  NodeName          = 'Paw21'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.24/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::24/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Privileged Access Workstation - Tier2'
        },

        @{  NodeName          = 'Paw22'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.84/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::84/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Privileged Access Workstation - Tier2'
        },

        @{  NodeName          = 'Paw23'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.144/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::144/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Privileged Access Workstation - Tier2'
        },

        @{  NodeName          = 'Paw24'
            UsedRoles         = @('Default', 'Paw')
            IPv4              = '192.168.0.214/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::214/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Privileged Access Workstation - Tier2'
        }

        #endregion

        #region ---------- Servers Tier 1 ------------------------------------------------------

        @{  NodeName          = 'Srv5'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.48/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::48/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Server 5'
        },

        @{  NodeName          = 'Srv6'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.108/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::108/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Server 6'
        },

        @{  NodeName          = 'Srv7'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.168/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::168/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Server 7'
        },

        @{  NodeName          = 'Srv8'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.238/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::238/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Server 8'
        },

        @{  NodeName          = 'Srv9'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.40/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::40/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Server 9'
        },

        @{  NodeName          = 'Srv10'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.100/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::100/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Server 10'
        },

        @{  NodeName          = 'Srv11'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.160/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::160/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Server 11'
        },

        @{  NodeName          = 'Srv12'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.230/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::230/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Server 12'
        },

        @{  NodeName          = 'Srv13'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.232/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::232/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 13'
        },

        @{  NodeName          = 'Srv14'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.162/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::162/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 14'
        },

        @{  NodeName          = 'Srv15'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.102/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::102/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 15'
        },

        @{  NodeName          = 'Srv16'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.42/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::42/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 16'
        },

        @{  NodeName          = 'Srv17'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.104/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::104/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 17'
        },

        @{  NodeName          = 'Srv18'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.164/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::164/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 18'
        },

        @{  NodeName          = 'Srv19'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.44/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::44/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 19'
        },

        @{  NodeName          = 'Srv20'
            UsedRoles         = @('Default', 'Server')
            IPv4              = '192.168.0.234/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::234/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Server 20'
        },

        #endregion

        #region ---------- PCs Tier 2 ----------------------------------------------------------

        @{  NodeName          = 'PC1'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.58/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::58/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC2'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.118/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::118/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC3'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.178/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::178/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC4'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.248/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::248/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC5'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.59/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::59/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC6'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.119/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::119/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC7'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.179/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::179/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC8'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.249/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::249/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC9'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.60/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::60/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC10'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.120/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::120/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC11'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.180/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::180/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'PC12'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.250/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::250/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Standard Workstation'
        },

        @{  NodeName          = 'Lap1'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.61/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::61/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Standard Laptop'
        },

        @{  NodeName          = 'Lap2'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.121/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::121/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Standard Laptop'
        },

        @{  NodeName          = 'Lap3'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.181/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::181/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Standard Laptop'
        },

        @{  NodeName          = 'Lap4'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.251/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::251/64'
            NetBIOSDomainName = 'EguibarIT'
            DnsDomainName     = 'EguibarIT.local'
            Description       = 'Standard Laptop'
        },

        @{  NodeName          = 'Lap5'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.62/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::62/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Standard Laptop'
        },

        @{  NodeName          = 'Lap6'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.122/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::122/64'
            NetBIOSDomainName = 'Admin'
            DnsDomainName     = 'Admin.local'
            Description       = 'Standard Laptop'
        },

        @{  NodeName          = 'Lap7'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.182/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::182/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Standard Laptop'
        },

        @{  NodeName          = 'Lap8'
            UsedRoles         = @('Default', 'PC')
            IPv4              = '192.168.0.252/23'
            IPv6              = 'fd36:46d4:a1a7:9d18::252/64'
            NetBIOSDomainName = 'Contoso'
            DnsDomainName     = 'Contoso.local'
            Description       = 'Standard Laptop'
        }

        #endregion

    ) #end AllNodes

    ########################################################################################

    Roles    = @(

        @{  RoleName        = 'Default'
            Services        = @(
                @{ DisplayName     = 'Windows Defender Antivirus Service'
                    Name           = 'WinDefend'
                    BuiltInAccount = 'LocalSystem'
                    StartupType    = 'Automatic'
                    State          = 'Running'
                    Description    = 'Helps protect users from malware and other potentially unwanted software'
                }
                @{
                    Name           = 'mpssvc'
                    BuiltInAccount = 'LocalService'
                    StartupType    = 'Automatic'
                    State          = 'Running'
                    Description    = 'Windows Defender Firewall helps protect your computer by preventing unauthorized users from gaining access to your computer through the Internet or a network.'
                    DisplayName    = 'Windows Defender Firewall'
                }
                @{
                    Name           = 'winrm'
                    BuiltInAccount = 'NetworkService'
                    StartupType    = 'Automatic'
                    State          = 'Running'
                    Description    = 'Windows Remote Management (WinRM) service implements the WS-Management protocol for remote management. WS-Management is a standard web services protocol used for remote software and hardware management. The WinRM service listens on the network for WS-Management requests and processes them. The WinRM Service needs to be configured with a listener using winrm.cmd command line tool or through Group Policy in order for it to listen over the network. The WinRM service provides access to WMI data and enables event collection. Event collection and subscription to events require that the service is running. WinRM messages use HTTP and HTTPS as transports. The WinRM service does not depend on IIS but is preconfigured to share a port with IIS on the same machine.  The WinRM service reserves the /wsman URL prefix. To prevent conflicts with IIS, administrators should ensure that any websites hosted on IIS do not use the /wsman URL prefix.'
                    DisplayName    = 'Windows Remote Management (WS-Management)'
                }
                @{
                    Name           = 'W32Time'
                    BuiltInAccount = 'LocalService'
                    StartupType    = 'Automatic'
                    State          = 'Running'
                    Description    = 'Maintains date and time synchronization on all clients and servers in the network. If this service is stopped, date and time synchronization will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start.'
                    DisplayName    = 'Windows Time'
                }
            )
            WindowsFeatures = @(
                'Windows-Defender',
                'NET-Framework-Features',
                'NET-Framework-Core',
                'NET-Framework-45-Features',
                'NET-Framework-45-Core',
                'PowerShell',
                'WoW64-Support'
            )
        },

        @{  RoleName        = 'DomainController'
            Services        = @(
                @{
                    Name           = 'DNS'
                    BuiltInAccount = 'LocalSystem'
                    StartupType    = 'Automatic'
                    State          = 'Running'
                    Description    = 'AD DS Domain Controllers Service. If this service is stoped, users will be unable to log on to the network. If this service is disabled, any services that explicitly depend on it will fail to start'
                    DisplayName    = 'Dns Server'
                }
            )
            WindowsFeatures = @(
                'AD-Domain-Services',
                'DNS',
                'FS-DFS-Namespace',
                'FS-DFS-Replication',
                'RSAT-AD-PowerShell',
                'GPMC'
            )
            DcDnsIPv4       = @(
                '192.168.0.1',
                '8.8.8.8',
                '8.8.4.4'
            )
            DcDnsIPv6       = @(
                'fd36:46d4:a1a7:9d18::1',
                '2001:4860:4860::8888',
                '2001:4860:4860::8844'
            )
        },

        @{  RoleName        = 'Server'
            Services        = @()
            WindowsFeatures = @(
                'BitLocker',
                'Windows-Server-Backup'
            )
        },

        @{  RoleName        = 'ADFS'
            Services        = @()
            WindowsFeatures = @()
        },

        @{  RoleName        = 'VMM'
            Services        = @()
            WindowsFeatures = @()
        },

        @{  RoleName        = 'SQL'
            Services        = @()
            WindowsFeatures = @()
        },

        @{  RoleName        = 'DFS'
            Services        = @(
                @{
                    Name           = 'DFS'
                    BuiltInAccount = 'LocalSystem'
                    StartupType    = 'Automatic'
                    State          = 'Running'
                    Description    = 'Enables you to group shared folders located on different servers into one or more logically structured namespaces. Each namespace appears to users as a single shared folder with a series of subfolders.'
                    DisplayName    = 'DFS Namespace'
                }
                @{
                    Name           = 'DFSR'
                    BuiltInAccount = 'LocalSystem'
                    StartupType    = 'Automatic'
                    State          = 'Running'
                    Description    = 'Enables you to synchronize folders on multiple servers across local or wide area network (WAN) network connections. This service uses the Remote Differential Compression (RDC) protocol to update only the portions of files that have changed since the last replication.'
                    DisplayName    = 'DFS Replication'
                }
            )
            WindowsFeatures = @(
                'FS-DFS-Namespace',
                'FS-DFS-Replication'
            )
        },

        @{  RoleName        = 'DscPullSrv'
            Services        = @()
            WindowsFeatures = @(
                'DSC-Service',
                'RSAT-AD-PowerShell'
            )
        },

        @{  RoleName        = 'wsus'
            Services        = @()
            WindowsFeatures = @(
                'UpdateServices',
                'UpdateServices-WidDB',
                'UpdateServices-Services'
            )
        },

        @{  RoleName                  = 'CA'
            Services                  = @(
                @{
                    Name           = 'CertSvc'
                    BuiltInAccount = 'LocalSystem'
                    StartupType    = 'Automatic'
                    State          = 'Running'
                    Description    = 'Creates, manages, and removes X.509 certificates for applications such as S/MIME and SSL. If this service is stopped, certificates will not be created. If this service is disabled, any services that explicitly depend on it will fail to start.'
                    DisplayName    = 'Active Directory Certificate Services'
                }
            )
            WindowsFeatures           = @(
                'AD-Certificate',
                'ADCS-Cert-Authority',
                'ADCS-web-enrollment'
            )
            CAType                    = 'EnterpriseRootCA'
            CACommonName              = 'Enterprise-CA'
            CADistinguishedNameSuffix = ''
            ValidityPeriod            = 'Years'
            ValidityPeriodUnits       = 5
            CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
            HashAlgorithmName         = 'SHA256'
            KeyLength                 = 4096
        },

        @{  RoleName        = 'Scom'
            Services        = @()
            WindowsFeatures = @()
        },

        @{  RoleName        = 'Sccm'
            Services        = @()
            WindowsFeatures = @()
        },

        @{  RoleName        = 'MDT'
            Services        = @()
            WindowsFeatures = @(
                'WDS',
                'WDS-Transport'
            )
        },

        @{  RoleName        = 'Wac'
            Services        = @()
            WindowsFeatures = @()
        },

        @{  RoleName        = 'PAW'
            Services        = @()
            WindowsFeatures = @(
                'GPMC',
                'RSAT-AD-Tools',
                'RSAT-AD-PowerShell',
                'RSAT-AD-AdminCenter',
                'RSAT-ADDS-Tools',
                'RSAT-Feature-Tools-BitLocker',
                'UpdateServices-RSAT',
                'UpdateServices-API',
                'RSAT-DNS-Server'
            )
        },

        @{  RoleName        = 'PC'
            Services        = @()
            WindowsFeatures = @()
        },

        @{  RoleName        = 'Lap'
            Services        = @()
            WindowsFeatures = @()
        }

    ) # End Roles

    ########################################################################################

    ProdDom  = @{
        DomainName     = 'EguibarIT.local'
        DomainDN       = 'DC=EguibarIT,DC=local'
        DCDatabasePath = 'C:\NTDS'
        DCLogPath      = 'C:\NTDS'
        SysvolPath     = 'C:\Sysvol'
        DomainMode     = 'Windows2016Domain'
        ForestMode     = 'Windows20116Forest'
    }

    ########################################################################################

    AdminDom = @{
        DomainName     = 'Admin.local'
        DomainDN       = 'DC=Admin,DC=local'
        DCDatabasePath = 'C:\NTDS'
        DCLogPath      = 'C:\NTDS'
        SysvolPath     = 'C:\Sysvol'
        DomainMode     = 'Windows2016Domain'
        ForestMode     = 'Windows20116Forest'
    }

}
