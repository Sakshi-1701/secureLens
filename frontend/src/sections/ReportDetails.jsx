import React, { useEffect, useMemo, useState } from 'react'
import { Table, TableBody, TableCell, TableHead, TableRow, Collapse, IconButton, Paper, LinearProgress, Button } from '@mui/material'
import { KeyboardArrowDown, KeyboardArrowUp } from '@mui/icons-material'
import { listReports, getResults, getStatus, deleteReport, sendReport, downloadReport } from '../services/api'

function Row({ plugin }) {
  const [open, setOpen] = useState(false)
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState(plugin.scanStatus)

  useEffect(() => {
    const id = setInterval(async () => {
      const { data } = await getStatus(plugin.id)
      setStatus(data)
    }, 4000)
    return () => clearInterval(id)
  }, [plugin.id])

  const loadResults = async () => {
    setLoading(true)
    const { data } = await getResults(plugin.id)
    setRows(data)
    setLoading(false)
  }

  useEffect(() => {
    if (open) loadResults()
  }, [open])

  const onDelete = async () => {
    await deleteReport(plugin.id)
    window.location.reload()
  }

  const onSend = async () => {
    const to = prompt('Send report to email:')
    if (!to) return
    await sendReport(to, plugin.id)
  }

  const onDownload = async () => {
    const res = await downloadReport(plugin.id)
    const url = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = url
    a.download = `${plugin.id}-report.pdf`
    a.click()
  }

  return (
    <>
      <TableRow hover className="hover:bg-orange-50">
        <TableCell>
          <IconButton size="small" onClick={() => setOpen(!open)}>
            {open ? <KeyboardArrowUp /> : <KeyboardArrowDown />}
          </IconButton>
        </TableCell>
        <TableCell className="font-medium">{plugin.pluginName}</TableCell>
        <TableCell>{status}</TableCell>
        <TableCell>
          <div className="flex gap-2">
            <Button size="small" variant="outlined" className="!border-orange-500 !text-orange-500 hover:!bg-orange-50" onClick={onSend}>Send</Button>
            <Button size="small" variant="contained" className="!bg-orange-500 hover:!bg-orange-600" onClick={onDownload}>PDF</Button>
            <Button size="small" variant="text" color="error" onClick={onDelete}>Delete</Button>
          </div>
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
          <Collapse in={open} timeout="auto" unmountOnExit>
            {loading && <LinearProgress />}
            <div className="p-4">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Severity</TableCell>
                    <TableCell>CVSS</TableCell>
                    <TableCell>ID</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Details</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows.map(r => (
                    <TableRow key={r.id} hover className="hover:bg-orange-50">
                      <TableCell>{r.severity}</TableCell>
                      <TableCell>{r.cvssScore}</TableCell>
                      <TableCell>{r.vulnerabilityId}</TableCell>
                      <TableCell>{r.vulnerabilityName}</TableCell>
                      <TableCell>
                        <div className="space-y-3">
                          <div>
                            <div className="text-sm font-semibold">Description</div>
                            <Paper variant="outlined" className="p-3">
                              <pre className="whitespace-pre-wrap">{r.description}</pre>
                            </Paper>
                          </div>
                          <div>
                            <div className="text-sm font-semibold">AI-Powered Suggestion</div>
                            <Paper variant="outlined" className="p-3">
                              <pre className="whitespace-pre-wrap">{r.aiSuggestion}</pre>
                            </Paper>
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  )
}

export default function ReportDetails() {
  const [plugins, setPlugins] = useState([])
  useEffect(() => {
    listReports().then(({ data }) => setPlugins(data))
  }, [])

  return (
    <div>
      <h2 className="text-lg font-semibold mb-4">Reports</h2>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell />
            <TableCell>Plugin</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {plugins.map(p => (
            <Row key={p.id} plugin={p} />
          ))}
        </TableBody>
      </Table>
    </div>
  )
}


