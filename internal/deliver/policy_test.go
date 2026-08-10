package deliver

import (
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

func TestDMARCBuildsTheFullPolicy(t *testing.T) {
	got := DMARC("a.com", config.DMARC{
		Policy:          "quarantine",
		SubdomainPolicy: "reject",
		Pct:             50,
		RUA:             "mailto:dmarc@a.com",
		RUF:             "mailto:forensics@a.com",
	})

	if got.Name != "_dmarc.a.com" || got.Type != "TXT" || got.Kind != dns.KindDMARC {
		t.Errorf("record = %+v, want a TXT on _dmarc.a.com", got)
	}
	want := "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:dmarc@a.com; ruf=mailto:forensics@a.com"
	if got.Content != want {
		t.Errorf("content = %q,\nwant                %q", got.Content, want)
	}
}

func TestDMARCOmitsEmptyTags(t *testing.T) {
	got := DMARC("a.com", config.DMARC{Policy: "none", Pct: 100})

	if got.Content != "v=DMARC1; p=none; pct=100" {
		t.Errorf("content = %q, want no sp, rua, or ruf tags", got.Content)
	}
}

func TestDMARCMixesOptionalTags(t *testing.T) {
	got := DMARC("a.com", config.DMARC{Policy: "reject", Pct: 100, RUA: "mailto:x@a.com"})

	if got.Content != "v=DMARC1; p=reject; pct=100; rua=mailto:x@a.com" {
		t.Errorf("content = %q, want sp unset but rua present", got.Content)
	}
}

func TestTLSRptRecord(t *testing.T) {
	got := TLSRpt("a.com", "mailto:tls@a.com")

	if got.Name != "_smtp._tls.a.com" || got.Kind != dns.KindTLSRpt {
		t.Errorf("record = %+v, want a TXT on _smtp._tls.a.com", got)
	}
	if got.Content != "v=TLSRPTv1; rua=mailto:tls@a.com" {
		t.Errorf("content = %q", got.Content)
	}
}

func TestBIMIWithAndWithoutVMC(t *testing.T) {
	withVMC := BIMI("a.com", config.BIMI{Logo: "https://a.com/logo.svg", VMC: "https://a.com/vmc.pem"})
	if withVMC.Name != "default._bimi.a.com" || withVMC.Kind != dns.KindBIMI {
		t.Errorf("record = %+v, want a TXT on default._bimi.a.com", withVMC)
	}
	if withVMC.Content != "v=BIMI1; l=https://a.com/logo.svg; a=https://a.com/vmc.pem" {
		t.Errorf("content = %q", withVMC.Content)
	}

	withoutVMC := BIMI("a.com", config.BIMI{Logo: "https://a.com/logo.svg"})
	if withoutVMC.Content != "v=BIMI1; l=https://a.com/logo.svg" {
		t.Errorf("content = %q, want no a= tag", withoutVMC.Content)
	}
}
