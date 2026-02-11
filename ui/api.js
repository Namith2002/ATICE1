// ============================================================================
// ATICE Advanced API Client
// ============================================================================

const API_BASE = "http://localhost:8000/api/v1";

/**
 * Base API request handler with authentication
 */
async function apiRequest(method, endpoint, data = null, customHeaders = {}) {
  const token = localStorage.getItem("aticeToken");
  
  const headers = {
    "Content-Type": "application/json",
    ...customHeaders
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const options = {
    method,
    headers
  };

  if (data && (method === "POST" || method === "PATCH")) {
    options.body = JSON.stringify(data);
  }

  const url = endpoint.startsWith("http") ? endpoint : `${API_BASE}${endpoint}`;

  try {
    const response = await fetch(url, options);

    if (response.status === 401) {
      // Token expired
      localStorage.removeItem("aticeToken");
      window.location.reload();
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error(`API Error (${method} ${endpoint}):`, error);
    throw error;
  }
}

// ============================================================================
// Authentication Endpoints
// ============================================================================

/**
 * Login with username and password
 */
async function login(username, password) {
  return apiRequest("POST", "/auth/login", { username, password });
}

// ============================================================================
// IOC Endpoints
// ============================================================================

/**
 * Create or update an IOC
 */
async function createIOC(ioc) {
  return apiRequest("POST", "/iocs", ioc);
}

/**
 * Batch ingest multiple IOCs
 */
async function batchIngestIOCs(iocs, source = "batch_import") {
  return apiRequest("POST", "/iocs/batch", { iocs, source });
}

/**
 * Get list of IOCs with optional filtering
 */
async function listIOCs(skip = 0, limit = 50, typeFilter = null, threatLevel = null) {
  let query = `?skip=${skip}&limit=${limit}`;
  if (typeFilter) query += `&type_filter=${typeFilter}`;
  if (threatLevel) query += `&threat_level=${threatLevel}`;
  return apiRequest("GET", `/iocs${query}`);
}

/**
 * Get a specific IOC by ID
 */
async function getIOC(iocId) {
  return apiRequest("GET", `/iocs/${iocId}`);
}

/**
 * Update an IOC
 */
async function updateIOC(iocId, updates) {
  return apiRequest("PATCH", `/iocs/${iocId}`, updates);
}

/**
 * Delete an IOC
 */
async function deleteIOC(iocId) {
  return apiRequest("DELETE", `/iocs/${iocId}`);
}

// ============================================================================
// Analysis & Correlation Endpoints
// ============================================================================

/**
 * Get correlations between IOCs
 */
async function getCorrelations(threshold = 0.5) {
  return apiRequest("GET", `/correlations?threshold=${threshold}`);
}

/**
 * Run threat analysis
 */
async function analyzethreats() {
  return apiRequest("POST", "/analyze");
}

/**
 * Search IOCs by query
 */
async function searchIOCs(query) {
  return apiRequest("POST", `/search?query=${encodeURIComponent(query)}`);
}

/**
 * Get threat score for an IOC
 */
async function getIOCScore(iocId) {
  return apiRequest("GET", `/score/${iocId}`);
}

// ============================================================================
// System & Monitoring Endpoints
// ============================================================================

/**
 * Health check
 */
async function healthCheck() {
  return apiRequest("GET", "/health");
}

/**
 * Get system statistics
 */
async function getStats() {
  return apiRequest("GET", "/stats");
}

/**
 * Export IOCs in specified format
 */
async function exportIOCs(format = "json") {
  return apiRequest("GET", `/export?format=${format}`);
}

// ============================================================================
// Error Handling Wrapper
// ============================================================================

/**
 * Wrap API calls with error handling
 */
async function withErrorHandling(apiCall, errorCallback) {
  try {
    return await apiCall();
  } catch (error) {
    if (errorCallback) {
      errorCallback(error);
    } else {
      console.error("API Error:", error.message);
    }
    throw error;
  }
}

// ============================================================================
// Batch Operations
// ============================================================================

/**
 * Ingest multiple IOCs from array
 */
async function ingestMultipleIOCs(iocArray, source = "bulk_import") {
  const batches = [];
  for (let i = 0; i < iocArray.length; i += 50) {
    batches.push(iocArray.slice(i, i + 50));
  }

  const results = [];
  for (const batch of batches) {
    try {
      const result = await batchIngestIOCs(batch, source);
      results.push(...result);
    } catch (error) {
      console.error("Batch ingest error:", error);
    }
  }

  return results;
}

/**
 * Delete multiple IOCs
 */
async function deleteMultipleIOCs(iocIds) {
  const results = [];
  for (const id of iocIds) {
    try {
      const result = await deleteIOC(id);
      results.push(result);
    } catch (error) {
      console.error(`Failed to delete IOC ${id}:`, error);
    }
  }
  return results;
}
