# api.yaml
policy_rego: |
  package apikey

  # If no team matches the user's groups, fall back
  default fallback := ["public"]

  # Collect classifications for any team whose groups intersect with input.user.groups
  class_set[c] {
    mf := data.metadata.metadata_filter
    team := mf[_]
    some i
    g := team.groups[i]
    input.user.groups[_] == g
    c := team.classification[_]
  }

  classes := sort([c | c := class_set[_]])

  # Final output
  metadata_filter := {"classification": classes} { count(classes) > 0 }
  metadata_filter := {"classification": fallback} { count(classes) == 0 }

# Rest of your existing YAML config
claims:
  # ... (original content)

metadata:
  metadata_filter:
    team1:
      groups: ["grp_tier1", "unix"]
      classification: ["confidential", "proprietary"]
    team2:
      groups: ["grp_tier2", "contributors"]
      classification: ["confidential"]




====================================
package api.metadata_filter

default filtered_classifications = []

# Main rule to get classifications for user's groups
filtered_classifications[classification] {
    # Get all team entries that match any of the user's groups
    some team_name
    team_data := input.metadata.metadata_filter[team_name]
    group_matches(team_data.groups, input.api_key.ad_groups)
    classification := team_data.classification[_]
}

# Helper function to check group matches
group_matches(team_groups, user_groups) {
    some i
    team_groups[i] == user_groups[_]
}

===================================

# api.yaml
policies:
  metadata_filter:
    # OPA policy defined in YAML (uses same logic as Rego but different syntax)
    allow:
      - input:
          api_key:
            ad_groups: 
              - "{{ .groups }}"
          metadata:
            metadata_filter: 
              "{{ .team }}":
                groups: 
                  - "{{ .team_groups }}"
                classification: "{{ .classifications }}"

# Rest of your existing YAML config
claims: 
  # ... (original content)
metadata:
  metadata_filter:
    team1:
      groups: ["grp_tier1", "unix"]
      classification: ["confidential", "proprietary"]
    team2:
      groups: ["grp_tier2", "contributors"]
      classification: ["confidential"]
