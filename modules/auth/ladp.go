package auth

import (
	"fmt"

	"github.com/GoAdminGroup/go-admin/modules/config"
	"github.com/GoAdminGroup/go-admin/modules/db"
	"github.com/GoAdminGroup/go-admin/plugins/admin/models"
	"github.com/go-ldap/ldap/v3"
)

// CheckLdap check the password and username with ldap and return the user model.
func CheckLdap(password string, username string, conn db.Connection) (user models.UserModel, ok bool) {

	user = models.User().SetConn(conn).FindByUserName(username)

	if user.IsEmpty() {
		ok = false
	} else {
		if checkLdapPassword(config.GetLdapHost(), config.GetLdapBind(), password, password) == nil {
			ok = true
			user, _ = models.User().SetConn(conn).New(username, password, username, "")
			user = user.WithRoles().WithPermissions().WithMenus()
		} else {
			ok = false
		}
	}
	return
}

func checkLdapPassword(ldapServer string, bind string, username, password string) error {
	l, err := ldap.DialURL(ldapServer)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	conn, err := ldap.DialURL(ldapServer)
	if err != nil {
		return err
	}

	result, err := conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: fmt.Sprintf(bind, username),
		Password: password,
	})
	if err != nil {
		return err
	}
	fmt.Printf("%+v\n", result)

	_, err = conn.WhoAmI(nil)
	if err != nil {
		return err
	}
	return nil
}
