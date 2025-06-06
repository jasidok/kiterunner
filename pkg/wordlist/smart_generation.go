package wordlist

import (
	"strings"

	"github.com/assetnote/kiterunner2/pkg/analysis"
	"github.com/assetnote/kiterunner2/pkg/http"
)

// SmartWordlistGenerator generates context-aware wordlists
type SmartWordlistGenerator struct {
	baseWordlists map[string][]string
}

// NewSmartWordlistGenerator creates a new smart wordlist generator
func NewSmartWordlistGenerator() *SmartWordlistGenerator {
	return &SmartWordlistGenerator{
		baseWordlists: initializeBaseWordlists(),
	}
}

// GenerateContextualWordlist creates a wordlist based on discovered technologies and context
func (swg *SmartWordlistGenerator) GenerateContextualWordlist(intel *analysis.ResponseIntelligence, discoveredPaths []string) []string {
	var wordlist []string

	// Start with high-value generic paths
	wordlist = append(wordlist, swg.baseWordlists["generic"]...)

	// Add technology-specific paths
	for _, tech := range intel.Technologies {
		if techWordlist, exists := swg.baseWordlists[strings.ToLower(tech.Technology)]; exists {
			wordlist = append(wordlist, techWordlist...)
		}
	}

	// Add framework-specific paths
	for _, framework := range intel.Frameworks {
		if frameworkWordlist, exists := swg.baseWordlists[strings.ToLower(framework)]; exists {
			wordlist = append(wordlist, frameworkWordlist...)
		}
	}

	// Add database-specific paths
	for _, db := range intel.Databases {
		if dbWordlist, exists := swg.baseWordlists[strings.ToLower(db)]; exists {
			wordlist = append(wordlist, dbWordlist...)
		}
	}

	// Generate paths based on discovered endpoints
	generatedPaths := swg.generatePathVariations(discoveredPaths)
	wordlist = append(wordlist, generatedPaths...)

	// Generate API version variations
	apiVersions := swg.generateAPIVersions(intel.APIs)
	wordlist = append(wordlist, apiVersions...)

	// Generate parameter-based paths
	paramPaths := swg.generateParameterPaths(intel.Parameters)
	wordlist = append(wordlist, paramPaths...)

	return removeDuplicates(wordlist)
}

// generatePathVariations creates variations of discovered paths
func (swg *SmartWordlistGenerator) generatePathVariations(discoveredPaths []string) []string {
	var variations []string

	for _, path := range discoveredPaths {
		// Generate common variations
		variations = append(variations, swg.createPathVariations(path)...)
	}

	return variations
}

// createPathVariations generates multiple variations of a single path
func (swg *SmartWordlistGenerator) createPathVariations(basePath string) []string {
	var variations []string

	// Clean the base path
	basePath = strings.TrimPrefix(basePath, "/")
	basePath = strings.TrimSuffix(basePath, "/")

	if basePath == "" {
		return variations
	}

	// Add the original path
	variations = append(variations, "/"+basePath)
	variations = append(variations, "/"+basePath+"/")

	// Generate backup/temporary file variations
	backupExtensions := []string{".bak", ".backup", ".old", ".orig", ".tmp", ".temp", "~", ".save"}
	for _, ext := range backupExtensions {
		variations = append(variations, "/"+basePath+ext)
	}

	// Generate case variations
	variations = append(variations, "/"+strings.ToUpper(basePath))
	variations = append(variations, "/"+strings.ToLower(basePath))

	// Generate underscore/hyphen variations
	if strings.Contains(basePath, "-") {
		underscored := strings.ReplaceAll(basePath, "-", "_")
		variations = append(variations, "/"+underscored)
	}
	if strings.Contains(basePath, "_") {
		hyphenated := strings.ReplaceAll(basePath, "_", "-")
		variations = append(variations, "/"+hyphenated)
	}

	// Generate plural/singular variations
	if strings.HasSuffix(basePath, "s") && len(basePath) > 3 {
		// Try removing 's' for singular
		singular := strings.TrimSuffix(basePath, "s")
		variations = append(variations, "/"+singular)
	} else {
		// Add 's' for plural
		variations = append(variations, "/"+basePath+"s")
	}

	// Generate common path extensions
	pathParts := strings.Split(basePath, "/")
	if len(pathParts) > 0 {
		lastPart := pathParts[len(pathParts)-1]
		pathPrefix := strings.Join(pathParts[:len(pathParts)-1], "/")
		if pathPrefix != "" {
			pathPrefix = "/" + pathPrefix + "/"
		} else {
			pathPrefix = "/"
		}

		// Common action variations
		actions := []string{"list", "view", "edit", "delete", "create", "update", "new", "add", "remove", "show", "index"}
		for _, action := range actions {
			variations = append(variations, pathPrefix+lastPart+"/"+action)
			variations = append(variations, pathPrefix+action+"/"+lastPart)
		}

		// Admin variations
		adminPrefixes := []string{"admin", "administrator", "manage", "control"}
		for _, prefix := range adminPrefixes {
			variations = append(variations, "/"+prefix+"/"+basePath)
		}
	}

	return variations
}

// generateAPIVersions creates API version variations
func (swg *SmartWordlistGenerator) generateAPIVersions(discoveredAPIs []string) []string {
	var versions []string

	for _, api := range discoveredAPIs {
		versions = append(versions, swg.createAPIVersionVariations(api)...)
	}

	return versions
}

// createAPIVersionVariations generates version variations for an API path
func (swg *SmartWordlistGenerator) createAPIVersionVariations(apiPath string) []string {
	var variations []string

	// Extract base API path (remove version if present)
	basePath := apiPath
	versionPatterns := []string{"/v1", "/v2", "/v3", "/v4", "/v5", "/version1", "/version2", "/ver1", "/ver2"}

	for _, pattern := range versionPatterns {
		if strings.Contains(apiPath, pattern) {
			basePath = strings.ReplaceAll(apiPath, pattern, "")
			break
		}
	}

	// Generate version variations
	versionFormats := []string{
		"v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10",
		"version1", "version2", "version3",
		"ver1", "ver2", "ver3",
		"1.0", "2.0", "3.0",
		"1", "2", "3", "4", "5",
	}

	for _, version := range versionFormats {
		// Add version at different positions
		variations = append(variations, basePath+"/"+version)
		variations = append(variations, strings.ReplaceAll(basePath, "/api", "/api/"+version))

		if strings.HasPrefix(basePath, "/api") {
			variations = append(variations, "/api/"+version+strings.TrimPrefix(basePath, "/api"))
		}
	}

	return variations
}

// generateParameterPaths creates paths based on discovered parameters
func (swg *SmartWordlistGenerator) generateParameterPaths(parameters []string) []string {
	var paths []string

	for _, param := range parameters {
		// Create paths that might exist based on parameter names
		if len(param) > 2 {
			paths = append(paths, "/"+param)
			paths = append(paths, "/"+param+"/")
			paths = append(paths, "/api/"+param)
			paths = append(paths, "/admin/"+param)

			// If parameter suggests an object, try CRUD operations
			crudActions := []string{"create", "read", "update", "delete", "list", "view", "edit"}
			for _, action := range crudActions {
				paths = append(paths, "/"+param+"/"+action)
				paths = append(paths, "/"+action+"/"+param)
			}
		}
	}

	return paths
}

// initializeBaseWordlists creates the base wordlists for different technologies
func initializeBaseWordlists() map[string][]string {
	wordlists := make(map[string][]string)

	// Generic high-value paths
	wordlists["generic"] = []string{
		"/admin", "/administrator", "/dashboard", "/panel", "/control",
		"/manage", "/management", "/console", "/backend", "/admin.php",
		"/wp-admin", "/phpmyadmin", "/cpanel", "/webmail", "/mail",
		"/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
		"/swagger", "/api-docs", "/docs", "/documentation", "/openapi.json",
		"/config", "/configuration", "/settings", "/env", "/.env",
		"/debug", "/test", "/dev", "/development", "/staging",
		"/backup", "/backups", "/dump", "/sql", "/database",
		"/upload", "/uploads", "/files", "/media", "/assets",
		"/login", "/signin", "/auth", "/oauth", "/sso", "/logout",
		"/register", "/signup", "/user", "/users", "/profile", "/account",
		"/status", "/health", "/ping", "/version", "/info", "/metrics",
		"/.git", "/.svn", "/.hg", "/.bzr", "/CVS",
		"/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config",
		"/crossdomain.xml", "/clientaccesspolicy.xml",
	}

	// PHP-specific paths
	wordlists["php"] = []string{
		"/index.php", "/admin.php", "/login.php", "/config.php",
		"/database.php", "/db.php", "/connect.php", "/connection.php",
		"/phpinfo.php", "/info.php", "/test.php", "/debug.php",
		"/install.php", "/setup.php", "/upgrade.php", "/update.php",
		"/backup.php", "/dump.php", "/export.php", "/import.php",
		"/upload.php", "/file.php", "/files.php", "/download.php",
		"/search.php", "/includes", "/include", "/lib", "/libs",
		"/classes", "/class", "/functions.php", "/common.php",
	}

	// ASP.NET-specific paths
	wordlists["asp.net"] = []string{
		"/default.aspx", "/admin.aspx", "/login.aspx", "/web.config",
		"/global.asax", "/app_data", "/app_code", "/bin",
		"/webform1.aspx", "/page1.aspx", "/secure", "/members",
		"/elmah.axd", "/trace.axd", "/webresource.axd",
		"/scriptresource.axd", "/handlers", "/modules",
	}

	// Java/Spring-specific paths
	wordlists["java"] = []string{
		"/admin", "/manager", "/console", "/actuator", "/actuator/health",
		"/actuator/info", "/actuator/env", "/actuator/configprops",
		"/actuator/mappings", "/actuator/trace", "/actuator/dump",
		"/spring", "/struts", "/hibernate", "/WEB-INF", "/META-INF",
		"/classes", "/lib", "/jsp", "/servlet", "/action",
	}

	// Node.js/Express-specific paths
	wordlists["express"] = []string{
		"/node_modules", "/package.json", "/npm-debug.log",
		"/server.js", "/app.js", "/index.js", "/main.js",
		"/routes", "/middleware", "/controllers", "/models",
		"/views", "/public", "/static", "/assets",
	}

	// Python/Django-specific paths
	wordlists["django"] = []string{
		"/admin", "/admin/", "/django-admin", "/manage.py",
		"/settings.py", "/urls.py", "/views.py", "/models.py",
		"/static", "/media", "/templates", "/locale",
		"/requirements.txt", "/wsgi.py", "/asgi.py",
	}

	// Python/Flask-specific paths
	wordlists["flask"] = []string{
		"/app.py", "/main.py", "/run.py", "/wsgi.py",
		"/static", "/templates", "/instance", "/migrations",
		"/requirements.txt", "/config.py", "/models.py",
	}

	// WordPress-specific paths
	wordlists["wordpress"] = []string{
		"/wp-admin", "/wp-content", "/wp-includes", "/wp-config.php",
		"/wp-login.php", "/wp-cron.php", "/wp-load.php", "/wp-blog-header.php",
		"/wp-content/themes", "/wp-content/plugins", "/wp-content/uploads",
		"/xmlrpc.php", "/wp-trackback.php", "/wp-comments-post.php",
	}

	// Database-specific paths
	wordlists["mysql"] = []string{
		"/phpmyadmin", "/pma", "/mysql", "/database", "/db",
		"/adminer.php", "/dbadmin", "/mysqladmin", "/sql",
	}

	wordlists["postgresql"] = []string{
		"/pgadmin", "/postgres", "/postgresql", "/pg", "/database",
	}

	wordlists["mongodb"] = []string{
		"/mongo", "/mongodb", "/mongo-express", "/db", "/database",
	}

	// Cloud service paths
	wordlists["aws"] = []string{
		"/.aws", "/aws", "/s3", "/ec2", "/lambda", "/cloudformation",
		"/elastic", "/elasticbeanstalk", "/iam", "/cloudwatch",
	}

	return wordlists
}

// GenerateRoutes converts wordlist paths to Route objects
func (swg *SmartWordlistGenerator) GenerateRoutes(wordlist []string, methods []http.Method) []*http.Route {
	var routes []*http.Route

	if len(methods) == 0 {
		methods = []http.Method{http.GET, http.POST, http.PUT, http.DELETE, http.PATCH}
	}

	for _, path := range wordlist {
		for _, method := range methods {
			route := &http.Route{
				Path:   []byte(path),
				Method: method,
			}
			routes = append(routes, route)
		}
	}

	return routes
}

// GenerateHighValueRoutes creates routes for high-value targets based on intelligence
func (swg *SmartWordlistGenerator) GenerateHighValueRoutes(intel *analysis.ResponseIntelligence) []*http.Route {
	var paths []string

	// High-value admin paths
	adminPaths := []string{
		"/admin", "/administrator", "/admin.php", "/admin.aspx",
		"/dashboard", "/panel", "/control", "/manage", "/backend",
		"/console", "/cpanel", "/webmail", "/phpmyadmin",
	}
	paths = append(paths, adminPaths...)

	// High-value API paths
	apiPaths := []string{
		"/api", "/api/v1", "/api/v2", "/rest", "/graphql",
		"/swagger", "/api-docs", "/openapi.json", "/docs",
	}
	paths = append(paths, apiPaths...)

	// Technology-specific high-value paths
	for _, tech := range intel.Technologies {
		switch strings.ToLower(tech.Technology) {
		case "wordpress":
			paths = append(paths, "/wp-admin", "/wp-login.php", "/wp-config.php")
		case "drupal":
			paths = append(paths, "/user", "/admin", "/?q=admin")
		case "joomla":
			paths = append(paths, "/administrator", "/component", "/modules")
		case "spring":
			paths = append(paths, "/actuator", "/actuator/env", "/actuator/health")
		case "django":
			paths = append(paths, "/admin", "/admin/")
		}
	}

	// Generate routes with available HTTP methods
	methods := []http.Method{http.GET, http.POST, http.PUT, http.DELETE, http.PATCH}
	return swg.GenerateRoutes(removeDuplicates(paths), methods)
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}
