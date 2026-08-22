package config

import "net"

type Client struct {
	ID       string `yaml:"id"`
	Secret   string `yaml:"secret"`
	ObjectID string `yaml:"object_id"`
}

type Config struct {
	TenantID             string   `yaml:"tenant_id"`
	SubscriptionID       string   `yaml:"subscription_id"`
	DefaultResourceGroup string   `yaml:"default_resource_group"`
	ListenerAddr         string   `yaml:"listener_addr"`
	ARMHost              string   `yaml:"arm_host"`
	LoginHost            string   `yaml:"login_host"`
	Clients              []Client `yaml:"clients"`
}

func Default() Config {
	config := Config{
		TenantID:             "11111111-1111-1111-1111-111111111111",
		SubscriptionID:       "22222222-2222-2222-2222-222222222222",
		DefaultResourceGroup: "default-rg",
		ListenerAddr:         "127.0.0.1:8443",
		ARMHost:              "management.localhost",
		LoginHost:            "login.localhost",
		Clients: []Client{{
			ID:       "33333333-3333-3333-3333-333333333333",
			Secret:   "provisio-secret",
			ObjectID: "44444444-4444-4444-4444-444444444444",
		}},
	}

	return config
}

func (c Config) LoginBaseURL() string {
	_, port, err := net.SplitHostPort(c.ListenerAddr)
	if err != nil {
		return "https://" + c.LoginHost
	}
	return "https://" + c.LoginHost + ":" + port
}

func (c Config) FindClient(id string) (Client, bool) {
	for _, cl := range c.Clients {
		if cl.ID == id {
			return cl, true
		}
	}
	return Client{}, false
}
