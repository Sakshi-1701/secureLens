import React, { useState } from 'react'
import { Button, TextField } from '@mui/material'
import { uploadZip, uploadGit, triggerScan } from '../services/api'

/**
 * @returns {JSX.Element}
 */
export default function UploadPlugin() {
  const [pluginName, setPluginName] = useState('')
  const [gitUrl, setGitUrl] = useState('')
  const [file, setFile] = useState(null)
  const [createdPluginId, setCreatedPluginId] = useState(null)

  const onUploadZip = async () => {
    if (!file || !pluginName) {
      alert('Please provide both plugin name and select a ZIP file')
      return
    }
    try {
      const { data } = await uploadZip(pluginName, file)
      setCreatedPluginId(data.id)
      alert('Upload successful! Plugin ID: ' + data.id)
    } catch (error) {
      alert('Upload failed: ' + (error.response?.data || error.message))
    }
  }

  const onUploadGit = async () => {
    if (!gitUrl || !pluginName) {
      alert('Please provide both plugin name and Git URL')
      return
    }
    try {
      const { data } = await uploadGit(pluginName, gitUrl)
      setCreatedPluginId(data.id)
      alert('Git URL saved! Plugin ID: ' + data.id)
    } catch (error) {
      alert('Git URL save failed: ' + (error.response?.data || error.message))
    }
  }

  const onScan = async () => {
    if (!createdPluginId) return
    await triggerScan(createdPluginId)
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold mb-2">Upload Plugin</h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <TextField label="Plugin Name" size="small" value={pluginName} onChange={e => setPluginName(e.target.value)} />
        <input type="file" accept=".zip" onChange={e => setFile(e.target.files?.[0] || null)} className="border rounded-lg p-2" />
        <Button variant="contained" className="!bg-orange-500 hover:!bg-orange-600" onClick={onUploadZip}>Upload ZIP</Button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <TextField label="Git URL" size="small" value={gitUrl} onChange={e => setGitUrl(e.target.value)} />
        <div />
        <Button variant="outlined" className="!border-orange-500 !text-orange-500 hover:!bg-orange-50" onClick={onUploadGit}>Save Git URL</Button>
      </div>
      <div>
        <Button disabled={!createdPluginId} variant="contained" className="!bg-orange-500 hover:!bg-orange-600" onClick={onScan}>Start Scan</Button>
      </div>
    </div>
  )
}


