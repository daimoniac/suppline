{{/*
Expand the name of the chart.
*/}}
{{- define "suppline.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "suppline.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "suppline.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "suppline.labels" -}}
helm.sh/chart: {{ include "suppline.chart" . }}
{{ include "suppline.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "suppline.selectorLabels" -}}
app.kubernetes.io/name: {{ include "suppline.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "suppline.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "suppline.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "suppline.frontend.labels" -}}
helm.sh/chart: {{ include "suppline.chart" . }}
{{ include "suppline.frontend.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: web-ui
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "suppline.frontend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "suppline.name" . }}-ui
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Generate registry URL based on release name
*/}}
{{- define "suppline.registryURL" -}}
{{- printf "%s-registry:%d" .Release.Name (.Values.registry.service.port | int) }}
{{- end }}

{{/*
Generate or use registry username
*/}}
{{- define "suppline.registryUsername" -}}
{{- if and .Values.registry.credentials .Values.registry.credentials.username }}
{{- .Values.registry.credentials.username }}
{{- else }}
{{- "suppline" }}
{{- end }}
{{- end }}

{{/*
Generate or use registry password
*/}}
{{- define "suppline.registryPassword" -}}
{{- if and .Values.registry.credentials .Values.registry.credentials.password }}
{{- .Values.registry.credentials.password }}
{{- else }}
{{- randAlphaNum 32 }}
{{- end }}
{{- end }}
