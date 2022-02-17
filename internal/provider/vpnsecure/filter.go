package vpnsecure

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (v *Vpnsecure) filterServers(selection settings.ServerSelection) (
	servers []models.VpnsecureServer, err error) {
	for _, server := range v.servers {
		switch {
		case
			utils.FilterByPossibilities(server.Region, selection.Regions),
			utils.FilterByPossibilities(server.City, selection.Cities),
			utils.FilterByPossibilities(server.Hostname, selection.Hostnames),
			*selection.FreeOnly && server.Premium:
		default:
			servers = append(servers, server)
		}
	}

	if len(servers) == 0 {
		return nil, utils.NoServerFoundError(selection)
	}

	return servers, nil
}
