{{- define "juggernaut.tag" -}}
{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "juggernaut.image" -}}
{{ .Values.image.registry }}/{{ . | toString }}
{{- end -}}

{{- define "juggernaut.labels" -}}
app.kubernetes.io/part-of: juggernaut
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "juggernaut.secretName" -}}
{{ .Values.secrets.existingSecret | default (printf "%s-secrets" .Release.Name) }}
{{- end -}}
