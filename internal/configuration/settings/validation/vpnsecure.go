package validation

import "github.com/qdm12/gluetun/internal/models"

func VpnsecureRegionChoices(servers []models.VpnsecureServer) (choices []string) {
	choices = make([]string, len(servers))
	for i := range servers {
		choices[i] = servers[i].Region
	}
	return makeUnique(choices)
}

func VpnsecureCityChoices(servers []models.VpnsecureServer) (choices []string) {
	choices = make([]string, len(servers))
	for i := range servers {
		choices[i] = servers[i].City
	}
	return makeUnique(choices)
}

func VpnsecureHostnameChoices(servers []models.VpnsecureServer) (choices []string) {
	choices = make([]string, len(servers))
	for i := range servers {
		choices[i] = servers[i].Hostname
	}
	return makeUnique(choices)
}
