import React from 'react'
import UploadPlugin from '../sections/UploadPlugin'
import ReportDetails from '../sections/ReportDetails'

export default function Dashboard() {
  return (
    <div className="flex flex-col gap-6">
      <div className="bg-white rounded-xl shadow-md p-6">
        <UploadPlugin />
      </div>
      <div className="bg-white rounded-xl shadow-md p-6">
        <ReportDetails />
      </div>
    </div>
  )
}


