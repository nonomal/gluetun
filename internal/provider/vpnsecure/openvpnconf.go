package vpnsecure

import (
	"fmt"
	"strconv"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/openvpn/parse"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (v *Vpnsecure) BuildConf(connection models.Connection,
	settings settings.OpenVPN) (lines []string, err error) {
	if len(settings.Ciphers) == 0 {
		settings.Ciphers = []string{constants.AES256cbc}
	}

	lines = []string{
		"client",
		"nobind",
		"tls-exit",
		"dev " + settings.Interface,
		"verb " + strconv.Itoa(*settings.Verbosity),

		// Vpnsecure specific
		"ping 10",
		"remote-cert-tls server",
		"auth-user-pass " + constants.OpenVPNAuthConf,
		"comp-lzo",
		"float",

		// Added constant values
		"auth-nocache",
		"mute-replay-warnings",
		"pull-filter ignore \"auth-token\"", // prevent auth failed loops
		"auth-retry nointeract",
		"suppress-timestamps",

		// Connection variables
		connection.OpenVPNProtoLine(),
		connection.OpenVPNRemoteLine(),
	}

	lines = append(lines, utils.CipherLines(settings.Ciphers, settings.Version)...)

	if connection.Protocol == constants.UDP {
		lines = append(lines, "explicit-exit-notify")
	}

	if *settings.Auth != "" {
		lines = append(lines, "auth "+*settings.Auth)
	}

	if settings.ProcessUser != "root" {
		lines = append(lines, "user "+settings.ProcessUser)
		lines = append(lines, "persist-tun")
		lines = append(lines, "persist-key")
	}

	if *settings.MSSFix > 0 {
		lines = append(lines, "mssfix "+strconv.Itoa(int(*settings.MSSFix)))
	}

	lines = append(lines, utils.WrapOpenvpnCA(constants.VpnsecureCA)...)
	lines = append(lines, utils.WrapOpenvpnCert(constants.VpnsecureCert)...)

	encryptedKeyData, err := parse.ExtractEncryptedPrivateKey([]byte(*settings.EncryptedPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("encrypted private key is not valid: %w", err)
	}
	lines = append(lines, utils.WrapOpenvpnEncryptedKey(encryptedKeyData)...)

	lines = append(lines, "")

	return lines, nil
}
