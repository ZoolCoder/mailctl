package ms365

// Graph payloads. Only the fields mailctl uses are declared; Graph sends more.

// domainDNSRecord is one entry from verificationDnsRecords or
// serviceConfigurationRecords. Graph discriminates the concrete type with
// @odata.type, so every type-specific field lives here and only those
// belonging to the reported type are populated.
type domainDNSRecord struct {
	ODataType        string `json:"@odata.type"`
	Label            string `json:"label"`
	RecordType       string `json:"recordType"`
	TTL              int    `json:"ttl"`
	SupportedService string `json:"supportedService"`
	IsOptional       bool   `json:"isOptional"`

	MailExchange  string `json:"mailExchange"`
	Preference    int    `json:"preference"`
	Text          string `json:"text"`
	CanonicalName string `json:"canonicalName"`
}

type graphDomain struct {
	ID                 string   `json:"id"`
	IsVerified         bool     `json:"isVerified"`
	SupportedServices  []string `json:"supportedServices"`
	AuthenticationType string   `json:"authenticationType"`
}

type graphUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	DisplayName       string `json:"displayName"`
	UsageLocation     string `json:"usageLocation"`
	AssignedLicenses  []struct {
		SkuID string `json:"skuId"`
	} `json:"assignedLicenses"`
}

type graphSku struct {
	SkuID         string `json:"skuId"`
	SkuPartNumber string `json:"skuPartNumber"`
	PrepaidUnits  struct {
		Enabled int `json:"enabled"`
	} `json:"prepaidUnits"`
	ConsumedUnits int `json:"consumedUnits"`
}

type passwordProfile struct {
	Password                      string `json:"password"`
	ForceChangePasswordNextSignIn bool   `json:"forceChangePasswordNextSignIn"`
}

type createUserRequest struct {
	AccountEnabled    bool            `json:"accountEnabled"`
	DisplayName       string          `json:"displayName"`
	MailNickname      string          `json:"mailNickname"`
	UserPrincipalName string          `json:"userPrincipalName"`
	UsageLocation     string          `json:"usageLocation"`
	PasswordProfile   passwordProfile `json:"passwordProfile"`
}

type addLicense struct {
	DisabledPlans []string `json:"disabledPlans"`
	SkuID         string   `json:"skuId"`
}

type assignLicenseRequest struct {
	AddLicenses    []addLicense `json:"addLicenses"`
	RemoveLicenses []string     `json:"removeLicenses"`
}

type patchDomainRequest struct {
	SupportedServices []string `json:"supportedServices"`
}
