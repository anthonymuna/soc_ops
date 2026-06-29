import { useState, useRef, useEffect } from 'react'
import { MessageSquare, Send, X, Bot, User, Sparkles, Terminal, ChevronDown, ChevronUp } from 'lucide-react'
import { getToken } from '../auth'

export default function ChatPanel({ onUnauth }) {
  const [isOpen, setIsOpen] = useState(false)
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'Hello! I am the NGAO Brain Assistant. Ask me anything about Wazuh alerts, source IPs, or security events in our East African infrastructure.'
    }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  
  const chatEndRef = useRef(null)

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages, isOpen])

  useEffect(() => {
    const handleInvestigate = async (e) => {
      setIsOpen(true)
      const msgText = e.detail.message
      if (!msgText) return
      
      setInput('')
      setError(null)
      setLoading(true)
      
      const userMsg = { role: 'user', content: msgText }
      setMessages(prev => [...prev, userMsg])
      
      const token = getToken()
      if (!token) {
        if (onUnauth) onUnauth()
        setLoading(false)
        return
      }
      
      try {
        const history = [...messages, userMsg].map(m => ({
          role: m.role,
          content: m.content
        }))
        
        const resp = await fetch('/api/brain/chat/', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ message: msgText, history })
        })
        
        if (resp.status === 401) {
          if (onUnauth) onUnauth()
          return
        }
        
        const resData = await resp.json()
        if (!resp.ok) {
          throw new Error(resData.message || `Chat request failed: ${resp.statusText}`)
        }
        
        setMessages(prev => [
          ...prev,
          {
            role: 'assistant',
            content: resData.reply,
            tool_calls: resData.tool_calls
          }
        ])
      } catch (err) {
        setError(err.message)
        setMessages(prev => [
          ...prev,
          {
            role: 'assistant',
            content: 'Sorry, I encountered an error while processing your request. Please try again.'
          }
        ])
      } finally {
        setLoading(false)
      }
    }
    window.addEventListener('ai-investigate', handleInvestigate)
    return () => window.removeEventListener('ai-investigate', handleInvestigate)
  }, [messages, onUnauth])

  const handleSend = async (e) => {
    if (e) e.preventDefault()
    const msg = input.trim()
    if (!msg || loading) return

    setInput('')
    setError(null)
    setLoading(true)

    // Add user message
    const userMsg = { role: 'user', content: msg }
    setMessages(prev => [...prev, userMsg])

    const token = getToken()
    if (!token) {
      if (onUnauth) onUnauth()
      setLoading(false)
      return
    }

    try {
      // Build history mapping
      const history = messages.map(m => ({
        role: m.role,
        content: m.content
      }))

      const resp = await fetch('/api/brain/chat/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: msg, history })
      })

      if (resp.status === 401) {
        if (onUnauth) onUnauth()
        return
      }

      const resData = await resp.json()
      if (!resp.ok) {
        throw new Error(resData.message || `Chat request failed: ${resp.statusText}`)
      }

      // Add assistant response
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: resData.reply,
          tool_calls: resData.tool_calls
        }
      ])
    } catch (err) {
      setError(err.message)
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: 'Sorry, I encountered an error while processing your request. Please try again.'
        }
      ])
    } finally {
      setLoading(false)
    }
  }

  const selectQuickPrompt = (promptText) => {
    setInput(promptText)
  }

  return (
    <>
      {/* Floating Toggle Button */}
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 p-4 rounded-full bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white shadow-lg shadow-cyan-500/20 transition-all hover:scale-105 active:scale-95 z-40 border border-cyan-400/25 flex items-center justify-center"
        title="AI Assistant Chat"
      >
        <MessageSquare className="w-6 h-6" />
        <span className="absolute -top-1 -right-1 bg-cyan-400 w-3 h-3 rounded-full animate-ping" />
        <span className="absolute -top-1 -right-1 bg-cyan-400 w-3 h-3 rounded-full" />
      </button>

      {/* Backdrop */}
      {isOpen && (
        <div
          onClick={() => setIsOpen(false)}
          className="fixed inset-0 bg-black/50 backdrop-blur-xs z-50 transition-opacity"
        />
      )}

      {/* Chat Drawer */}
      <div
        className={`fixed top-0 right-0 h-full w-full sm:w-[28rem] bg-soc-panel/95 backdrop-blur-md border-l border-soc-border shadow-2xl z-50 flex flex-col transition-transform duration-300 ${
          isOpen ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-soc-border bg-soc-panel">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-bold text-cyan-400 tracking-wider">NGAO BRAIN</h3>
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold block">
                LangChain Triage Assistant
              </span>
            </div>
          </div>
          <button
            onClick={() => setIsOpen(false)}
            className="text-slate-500 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Conversation Message List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((m, idx) => (
            <div key={idx} className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              {m.role === 'assistant' && (
                <div className="w-8 h-8 rounded-full bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center text-cyan-400 flex-shrink-0">
                  <Bot className="w-4 h-4" />
                </div>
              )}

              <div className="space-y-1.5 max-w-[80%]">
                <div
                  className={`p-3 rounded-lg text-xs leading-relaxed ${
                    m.role === 'user'
                      ? 'bg-cyan-600/15 text-slate-200 rounded-tr-none border border-cyan-500/20'
                      : 'bg-soc-border/40 text-slate-300 rounded-tl-none border border-soc-border'
                  }`}
                >
                  {m.content}
                </div>

                {/* Render intermediate tool calls if present */}
                {m.tool_calls && m.tool_calls.length > 0 && (
                  <div className="space-y-1">
                    {m.tool_calls.map((call, cidx) => (
                      <ToolCallItem key={cidx} call={call} />
                    ))}
                  </div>
                )}
              </div>

              {m.role === 'user' && (
                <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400 flex-shrink-0">
                  <User className="w-4 h-4" />
                </div>
              )}
            </div>
          ))}
          {loading && (
            <div className="flex gap-3 justify-start">
              <div className="w-8 h-8 rounded-full bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center text-cyan-400 flex-shrink-0">
                <Bot className="w-4 h-4 animate-bounce" />
              </div>
              <div className="bg-soc-border/40 text-slate-400 rounded-lg p-3 rounded-tl-none border border-soc-border text-xs italic flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-ping" />
                Thinking and fetching security intelligence...
              </div>
            </div>
          )}
          {error && (
            <div className="bg-rose-950/20 border border-rose-500/30 text-rose-400 text-[10px] p-2.5 rounded">
              {error}
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        {/* Quick Prompts Panel */}
        {messages.length === 1 && !loading && (
          <div className="px-4 py-2 bg-soc-panel/30 border-t border-soc-border/40">
            <span className="text-[10px] text-slate-600 uppercase tracking-widest font-semibold block mb-2">
              Quick Suggestions
            </span>
            <div className="flex flex-col gap-1.5">
              {[
                'Show critical alerts from the last 24 hours',
                'Analyze security event history for IP 10.0.0.1',
                'What is the reputation of IP 8.8.8.8?',
                'Are there any brute force attempts triaged?'
              ].map(qp => (
                <button
                  key={qp}
                  onClick={() => selectQuickPrompt(qp)}
                  className="text-left text-[11px] text-slate-400 hover:text-cyan-400 bg-soc-border/20 hover:bg-cyan-500/10 px-2.5 py-1.5 rounded transition-colors truncate border border-transparent hover:border-cyan-500/25"
                >
                  {qp}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input Form */}
        <form onSubmit={handleSend} className="p-4 border-t border-soc-border bg-soc-panel flex gap-2">
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            disabled={loading}
            placeholder="Ask AI Assistant..."
            className="flex-1 bg-soc-bg border border-soc-border focus:border-cyan-500 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none placeholder-slate-600 disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-3 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:hover:bg-cyan-600 text-white flex items-center justify-center transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </>
  )
}

function ToolCallItem({ call }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="border border-soc-border/60 bg-black/20 rounded overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-2 py-1 text-[9px] text-cyan-500/80 font-mono hover:bg-soc-border/20 transition-colors"
      >
        <div className="flex items-center gap-1">
          <Terminal className="w-3 h-3" />
          <span>Executed tool: {call.tool}</span>
        </div>
        {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
      </button>

      {expanded && (
        <div className="p-2 border-t border-soc-border/30 bg-black/40 text-[9px] text-slate-400 font-mono space-y-1.5">
          <div>
            <span className="text-slate-600 font-bold">Input:</span>
            <pre className="whitespace-pre-wrap mt-0.5 max-h-16 overflow-y-auto">
              {typeof call.input === 'object' ? JSON.stringify(call.input, null, 2) : String(call.input)}
            </pre>
          </div>
          <div>
            <span className="text-slate-600 font-bold">Output:</span>
            <pre className="whitespace-pre-wrap mt-0.5 max-h-24 overflow-y-auto">
              {call.output}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
