package vpnsecure

import (
	"math/rand"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Vpnsecure struct {
	servers    []models.VpnsecureServer
	randSource rand.Source
	utils.NoPortForwarder
}

func New(servers []models.VpnsecureServer, randSource rand.Source) *Vpnsecure {
	return &Vpnsecure{
		servers:         servers,
		randSource:      randSource,
		NoPortForwarder: utils.NewNoPortForwarding(constants.Vpnsecure),
	}
}
