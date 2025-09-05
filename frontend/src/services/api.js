import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
})

export const uploadZip = (pluginName, file) => {
  const form = new FormData()
  form.append('pluginName', pluginName)
  form.append('file', file)
  return api.post('/upload-plugin', form, { headers: { 'Content-Type': 'multipart/form-data' } })
}

export const uploadGit = (pluginName, gitUrl) => {
  const form = new URLSearchParams()
  form.append('pluginName', pluginName)
  form.append('gitUrl', gitUrl)
  return api.post('/upload-plugin/git', form)
}

export const triggerScan = (pluginId) => api.post(`/scan-plugin/${pluginId}`)
export const getStatus = (pluginId) => api.get(`/scan-status/${pluginId}`)
export const getResults = (pluginId) => api.get(`/scan-results/${pluginId}`)
export const listReports = () => api.get('/reports')
export const deleteReport = (pluginId) => api.delete(`/delete-report/${pluginId}`)
export const sendReport = (to, pluginId) => api.post(`/send-report/${pluginId}`, null, { params: { to } })
export const downloadReport = (pluginId) => api.get(`/download-report/${pluginId}`, { responseType: 'blob' })

export default api


