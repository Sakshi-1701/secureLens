import React from 'react'
import { Routes, Route } from 'react-router-dom'
import Dashboard from './pages/Dashboard'

export default function App() {
  return (
    <div className="min-h-screen bg-slate-100 font-inter text-slate-800">
      {/* Header Section */}
      <header className="bg-white shadow-sm border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <h1 className="text-3xl font-bold text-slate-800 text-center">
            Secure Lens 🔒
          </h1>
          <p className="text-sm text-slate-600 text-center mt-1">
            Advanced Security Scanning Platform
          </p>
        </div>
      </header>
      
      {/* Main Content */}
      <div className="max-w-7xl mx-auto py-6 px-4">
        <main>
          <Routes>
            <Route path="/" element={<Dashboard />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}


