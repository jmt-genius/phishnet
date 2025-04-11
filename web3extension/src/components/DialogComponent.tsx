// DialogComponent.tsx
import React from 'react';
import { Dialog, DialogClose, DialogContent, DialogTitle, DialogFooter } from './ui/dialog';

const DialogComponent = ({ data }) => {
  return (
    <Dialog open={true}>
      <DialogContent>
        <DialogTitle>Analysis Completed</DialogTitle>
        <pre>{JSON.stringify(data, null, 2)}</pre>
        <DialogFooter>
          <button className="btn" onClick={() => alert("Close the dialog")}>
            Close
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default DialogComponent;
