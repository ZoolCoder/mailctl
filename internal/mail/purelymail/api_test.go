package purelymail

import (
	"context"
	"strings"
	"testing"
)

// The destructive and credential-issuing calls had no tests. What matters in
// each is the endpoint and the exact field names: Purelymail's API takes a
// wrapper object per endpoint, so a wrong key is not a type error here — the
// request succeeds and does nothing, or acts on the wrong object.

func TestDeleteUserNamesTheAddressUnderUserName(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success"}`)

	if err := client.DeleteUser(context.Background(), "contact@example.com"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	if !strings.HasSuffix(rec.path, "/deleteUser") {
		t.Errorf("path = %q, want the deleteUser endpoint", rec.path)
	}
	if got := rec.body["userName"]; got != "contact@example.com" {
		t.Errorf("userName = %v, want the address; a wrong key deletes nothing and still reports success", got)
	}
}

// deleteDomain takes "name" while deleteUser takes "userName". The asymmetry is
// Purelymail's, and getting it wrong is silent.
func TestDeleteDomainNamesTheDomainUnderName(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success"}`)

	if err := client.DeleteDomain(context.Background(), "example.com"); err != nil {
		t.Fatalf("DeleteDomain: %v", err)
	}

	if !strings.HasSuffix(rec.path, "/deleteDomain") {
		t.Errorf("path = %q, want the deleteDomain endpoint", rec.path)
	}
	if got := rec.body["name"]; got != "example.com" {
		t.Errorf("name = %v, want the domain", got)
	}
	if _, wrong := rec.body["domainName"]; wrong {
		t.Error("sent domainName; deleteDomain takes name, unlike addDomain")
	}
}

func TestDeleteUserSurfacesARefusal(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"error","code":"NO_SUCH_USER","message":"no such user"}`)

	err := client.DeleteUser(context.Background(), "absent@example.com")
	if err == nil {
		t.Fatal("expected an error; a failed delete reported as success leaves the plan believing the mailbox is gone")
	}
	if !strings.Contains(err.Error(), "NO_SUCH_USER") {
		t.Errorf("error should carry Purelymail's own code; got %q", err)
	}
}

func TestModifyUserSendsOnlyTheFieldsSet(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success"}`)

	on := true
	changes := UserChanges{UserName: "contact@example.com", RequireTwoFactorAuthentication: &on}
	if err := client.ModifyUser(context.Background(), changes); err != nil {
		t.Fatalf("ModifyUser: %v", err)
	}

	if !strings.HasSuffix(rec.path, "/modifyUser") {
		t.Errorf("path = %q, want the modifyUser endpoint", rec.path)
	}
	if got := rec.body["requireTwoFactorAuthentication"]; got != true {
		t.Errorf("requireTwoFactorAuthentication = %v, want true", got)
	}
	// omitempty matters: sending a zero value for an unset field would silently
	// turn a setting off that the operator never mentioned.
	for _, key := range []string{"newPassword", "enablePasswordReset", "enableSearchIndexing"} {
		if _, present := rec.body[key]; present {
			t.Errorf("%s was sent although it was not set; an unset field must be omitted, not defaulted", key)
		}
	}
}

func TestCreateAppPasswordReturnsTheOnceOnlyCredential(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"appPassword":"generated-secret"}}`)

	got, err := client.CreateAppPassword(context.Background(), "contact@example.com", "phone")
	if err != nil {
		t.Fatalf("CreateAppPassword: %v", err)
	}

	if got != "generated-secret" {
		t.Errorf("app password = %q, want the value Purelymail returned; it cannot be read again", got)
	}
	if got := rec.body["userName"]; got != "contact@example.com" {
		t.Errorf("userName = %v", got)
	}
	if got := rec.body["name"]; got != "phone" {
		t.Errorf("name = %v, want phone", got)
	}
}

func TestCreateAppPasswordOmitsAnEmptyName(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"appPassword":"s"}}`)

	if _, err := client.CreateAppPassword(context.Background(), "contact@example.com", ""); err != nil {
		t.Fatalf("CreateAppPassword: %v", err)
	}

	if _, present := rec.body["name"]; present {
		t.Error("an empty name was sent; it should be omitted so Purelymail picks its own default")
	}
}

func TestDeleteAppPasswordIdentifiesByAddressAndName(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success"}`)

	if err := client.DeleteAppPassword(context.Background(), "contact@example.com", "phone"); err != nil {
		t.Fatalf("DeleteAppPassword: %v", err)
	}

	if !strings.HasSuffix(rec.path, "/deleteAppPassword") {
		t.Errorf("path = %q", rec.path)
	}
	if rec.body["userName"] != "contact@example.com" || rec.body["name"] != "phone" {
		t.Errorf("body = %v, want both the address and the credential name", rec.body)
	}
}

func TestDeletePasswordResetSendsAddressAndID(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success"}`)

	if err := client.DeletePasswordReset(context.Background(), "contact@example.com", "7"); err != nil {
		t.Fatalf("DeletePasswordReset: %v", err)
	}

	if !strings.HasSuffix(rec.path, "/deletePasswordReset") {
		t.Errorf("path = %q", rec.path)
	}
	if rec.body["userName"] != "contact@example.com" || rec.body["id"] != "7" {
		t.Errorf("body = %v, want the address and the method id", rec.body)
	}
}

func TestCheckAccountCreditReadsTheCredit(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"credit":"12.34"}}`)

	got, err := client.CheckAccountCredit(context.Background())
	if err != nil {
		t.Fatalf("CheckAccountCredit: %v", err)
	}

	if got != "12.34" {
		t.Errorf("credit = %q, want 12.34", got)
	}
	if !strings.HasSuffix(rec.path, "/checkAccountCredit") {
		t.Errorf("path = %q", rec.path)
	}
}
