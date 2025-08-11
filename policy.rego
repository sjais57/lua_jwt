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
opa eval -I \
  -d api.yaml \
  -d <(awk '
    BEGIN{block=0; indent=-1}
    /^[[:space:]]*policy_rego:[[:space:]]*\|[[:space:]]*$/ { block=1; indent=match($0,/[^ ]/)-1; next }
    block {
      this = match($0,/[^ ]/)-1
      if (this < indent + 2 && $0 !~ /^[[:space:]]*$/) exit
      sub(sprintf("^ {%d}", indent+2), "")
      print
    }
  ' api.yaml) \
  -i <(printf %s '{"user":{"name":"alice","groups":["grp_tier1","unix"]}}') \
  'data.apikey.metadata_filter' -f pretty
