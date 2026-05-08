package scan

type scanOptions struct {
	Discovery   discoveryOptions
	Web         webOptions
	Credentials credentialOptions
}

type discoveryOptions struct {
	Ports    string
	Threads  int
	Timeout  int
	Explicit bool
}

type webOptions struct {
	Dictionaries []string
	Rules        []string
	Word         string
	DefaultDict  bool
	Advance      bool
}

type credentialOptions struct {
	Users     []string
	Passwords []string
}

func resolveScanOptions(flags flags) scanOptions {
	ports := flags.Ports
	explicitDiscovery := false
	if flags.Port != "" {
		ports = flags.Port
		explicitDiscovery = true
	}
	return scanOptions{
		Discovery: discoveryOptions{
			Ports:    ports,
			Threads:  flags.Threads,
			Timeout:  flags.Timeout,
			Explicit: explicitDiscovery,
		},
		Web: webOptions{
			Dictionaries: append([]string(nil), flags.Dictionaries...),
			Rules:        append([]string(nil), flags.Rules...),
			Word:         flags.Word,
			DefaultDict:  flags.DefaultDict,
			Advance:      flags.Advance,
		},
		Credentials: credentialOptions{
			Users:     append([]string(nil), flags.Users...),
			Passwords: append([]string(nil), flags.Passwords...),
		},
	}
}

func (o scanOptions) hasWeakpassOverrides() bool {
	return len(o.Credentials.Users) > 0 || len(o.Credentials.Passwords) > 0
}

func (o scanOptions) hasDiscoveryOverrides() bool {
	return o.Discovery.Explicit
}

func (o scanOptions) hasWebOverrides() bool {
	return len(o.Web.Dictionaries) > 0 || len(o.Web.Rules) > 0 || o.Web.Word != "" || o.Web.DefaultDict || o.Web.Advance
}
