import React from 'react';

const Header = ({ user, onLogout, onSettings, onActivity, onAdmin, isAdmin }) => {
  return (
    <header className="header">
      <h2>File Manager</h2>
      {user && (
        <div className="user-info">
          {isAdmin && <button className="admin-button" onClick={onAdmin}>👑</button>}
          <button className="activity-button" onClick={onActivity}>📝</button>
          <button className="settings-button" onClick={onSettings}>⚙️</button>
          <span>Welcome, {user}</span>
          <button className="logout-button" onClick={onLogout}>Logout</button>
        </div>
      )}
    </header>
  );
};

export default Header; 