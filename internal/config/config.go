package config

type Config struct {
	TenantID             string `yaml:"tenant_id"`
	SubscriptionID       string `yaml:"subscription_id"`
	DefaultResourceGroup string `yaml:"default_resource_group"`
	ListenerAddr         string `yaml:"listener_addr"`
	ARMHost              string `yaml:"arm_host"`
	LoginHost            string `yaml:"login_host"`
}

func Default() Config {
	config := Config{
		TenantID:             "11111111-1111-1111-1111-111111111111",
		SubscriptionID:       "22222222-2222-2222-2222-222222222222",
		DefaultResourceGroup: "default-rg",
		ListenerAddr:         "localhost:8443",
		ARMHost:              "127.0.0.1",
		LoginHost:            "127.0.0.1",
	}

	return config
}
