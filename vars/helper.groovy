import groovy.json.JsonOutput
import groovy.json.JsonSlurper

// In your functions, use Globals.ruleIdList
def addRuleId(ruleId) {
    Globals.ruleIdList << ruleId
}

// Map SonarQube hotspots to issues format for SARIF conversion
def mapHotspotsToIssues(hotspots) {
    // check the len of issues array before collecting
    
    def hotspotArray = hotspots.hotspots
    if (!hotspotArray || hotspotArray.size() == 0) {
        return []
    }
    return hotspotArray.collect { hotspot ->
        [
            rule: hotspot.ruleKey,
            message: hotspot.message,
            filePath: hotspot.component ? hotspot.component.split(":")[1] : null,
            startLine: hotspot.textRange.startLine,
            endLine: hotspot.textRange.endLine,
            startColumn: hotspot.textRange.startOffset,
            endColumn: hotspot.textRange.endOffset,
            impacts: [ "severity" : hotspot.vulnerabilityProbability.toUpperCase() ],
            type: "HOTSPOT"
        ]
    }
}

def severityMap(severity){
    switch(severity) {
        case "MINOR":
            return "LOW"
        case "MAJOR":
            return "HIGH"
        case "CRITICAL":
        case "BLOCKER":
            return "VERY_HIGH"
        case "HIGH":
            return "HIGH"
        case "MEDIUM":
            return "MEDIUM"
        case "LOW":
            return "LOW"
    }
    return "INFORMATION"

}

def mapIssueToMatch(issues) {
    def issueArray = issues.issues
    if (!issueArray || issueArray.size() == 0) {
        return [] 
    }
    return issueArray.collect { issue ->
        [
            rule : issue.rule,
            message: issue.message,
            filePath: issue.component ? issue.component.split(":")[1] : null,
            startLine: issue.textRange.startLine,
            endLine: issue.textRange.endLine,
            startColumn: issue.textRange.startOffset,
            endColumn: issue.textRange.endOffset,
            impacts: [ "severity" : severityMap(issue.severity) ],
            type: issue.type,
        ]
    }
}


// Map issues directly to SARIF results format
def mapIssuesToSarif(issues, workspacePath) {
    return issues.collect { issue ->
        def snippetText = ""
        try {
            def snippetPath = workspacePath + "/" + issue.filePath
            snippetText = getVulnerableCodeSnippet(snippetPath, issue.startLine, issue.endLine)
        } catch (Exception e) {
            //println("Error extracting snippet from ${snippetPath}: ${e.message}")
            snippetText = ""
        }
        addRuleId(issue.rule)
        [
            ruleId: issue.rule,
            level : issue.impacts.severity,
            message:[
                text: issue.type + ': ' + issue.message
            ],
            fingerprints: issue.hash ? [ "0" : issue.hash ] : null,
            locations: [
                [
                    physicalLocation: [
                        artifactLocation: [
                            uri: issue.filePath
                        ],
                        region: [
                            startLine: issue.startLine,
                            startColumn: issue.startColumn,
                            endLine: issue.endLine,
                            endColumn: issue.endColumn,
                            snippet: [
                                text: snippetText
                            ]
                        ]
                    ]
                ]
            ]
        ]
    }
}

// Create a function to get the vulnerable code snippet using the physical uri and the start line and end lines
def getVulnerableCodeSnippet(uri, startLine, endLine) {
    if (!uri || !(new File(uri).exists())) {
        return new Exception("File not found: ${uri}")
    }
    def lines = new File(uri).readLines()
    def snippetText = lines[(startLine - 1)..(endLine - 1)].join('\n')
    return snippetText
}

// Groovy function to fetch issues from SonarQube API
def fetchSonarIssues(sonarHost, sonarToken, projectKey) {
    def url = "${sonarHost}/api/issues/search?componentKeys=${projectKey}&ps=500"
    def connection = new URL(url).openConnection()
    def authString = "${sonarToken}:"
    def authEncBytes = authString.bytes.encodeBase64().toString()
    connection.setRequestProperty("Authorization", "Basic ${authEncBytes}")
    connection.setRequestProperty("Accept", "application/json")
    connection.connect()
    def response = connection.inputStream.text
    return response
}

// Groovy function to fetch hotspots from SonarQube API
def fetchSonarHotspots(sonarHost, sonarToken, projectKey) {
    def url = "${sonarHost}/api/hotspots/search?projectKey=${projectKey}&ps=500"
    def connection = new URL(url).openConnection()
    def authString = "${sonarToken}:"
    def authEncBytes = authString.bytes.encodeBase64().toString()
    connection.setRequestProperty("Authorization", "Basic ${authEncBytes}")
    connection.setRequestProperty("Accept", "application/json")
    connection.connect()
    def response = connection.inputStream.text
    return response
}

// Groovy function to fetch Rule from SonarQube API
def fetchSonarRule(sonarHost, sonarToken, projectKey, ruleId) {
    def url = "${sonarHost}/api/rules/show?key=${ruleId}"
    def connection = new URL(url).openConnection()
    def authString = "${sonarToken}:"
    def authEncBytes = authString.bytes.encodeBase64().toString()
    connection.setRequestProperty("Authorization", "Basic ${authEncBytes}")
    connection.setRequestProperty("Accept", "application/json")
    connection.connect()
    def response = connection.inputStream.text
    return response
}


def makeRuleForSarif(sonarHost, sonarToken, projectKey) {
    def rules = []
    Globals.ruleIdList.unique().each { ruleId ->
        def ruleResp = fetchSonarRule(sonarHost, sonarToken, projectKey, ruleId)
        def ruleJson = new JsonSlurper().parseText(ruleResp)
        def r = ruleJson.rule
        if (r) {
            def sarifRule = [
                id: r.key,
                name: r.name ?: "",
                shortDescription: [
                    text: r.name ?: ""
                ],
                fullDescription: [
                    text: r.htmlDesc ?: ""
                ],
                help: [
                    text: r.mdDesc ?: r.htmlDesc ?: "",
                    uri: "https://sonarqube.example.com/coding_rules?open=${r.key}"
                ],
                properties: [
                    tags: r.tags ?: [],
                    severity: r.severity ?: "",
                    type: r.type ?: "",
                    lang: r.lang ?: "",
                    precision: severityMap(r.severity ?: "")
                ],
                
            ]
            rules << sarifRule
        }
    }
    return rules
}

// Combine both issues and hotspots into a single SARIF file
def getSarifOutput(url, token, projectKey, workspacePath, scannerVersion) {
    def jsonSlurper = new JsonSlurper()

    def issuesJson = fetchSonarIssues(url, token, projectKey)
    def hotspotsJson = fetchSonarHotspots(url, token, projectKey)

    def issuesData = jsonSlurper.parseText(issuesJson)
    def hotspotsData = jsonSlurper.parseText(hotspotsJson)

    def issuesSarif = mapIssuesToSarif(mapIssueToMatch(issuesData), workspacePath)
    def hotspotsSarif = mapIssuesToSarif(mapHotspotsToIssues(hotspotsData), workspacePath)

    // Combine both lists
    def combinedResults = issuesSarif + hotspotsSarif

    def sarifData = new LinkedHashMap()
    sarifData['\$schema'] = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json'
    sarifData['version'] = "2.1.0"
    sarifData['runs'] = [
        [
            tool: [
                driver: [
                    name: "SonarQube",
                    version: scannerVersion,
                    rules: makeRuleForSarif(url, token, projectKey)
                ]
            ],
            results: combinedResults,
            
        ]
    ]
    return JsonOutput.toJson(sarifData)
}
