package main

import "time"

type FileRecord struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Size               int64     `json:"size"`
	MimeType           string    `json:"mimeType"`
	SHA256             string    `json:"hash"`
	UploadType         string    `json:"uploadType"`
	UploadTime         time.Time `json:"uploadTime"`
	ExpiryTime         time.Time `json:"expiryTime"`
	ClientIP           string    `json:"clientIP"`
	StoredName         string    `json:"storedName"`
	DeleteTokenHash    string    `json:"deleteTokenHash,omitempty"`
	FolderID           string    `json:"folderId,omitempty"`
	Position           int       `json:"position,omitempty"`
	HasWarning         bool      `json:"hasWarning"`
	RiskLevel          string    `json:"riskLevel"`
	SuspiciousPatterns []string  `json:"suspiciousPatterns,omitempty"`
	Recommendations    []string  `json:"recommendations,omitempty"`
}

type FolderRecord struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	CreatedAt       time.Time `json:"createdAt"`
	ExpiryTime      time.Time `json:"expiryTime"`
	ManageTokenHash string    `json:"manageTokenHash"`
}

type DiskIndex struct {
	Files   map[string]*FileRecord   `json:"files"`
	Folders map[string]*FolderRecord `json:"folders"`
}
