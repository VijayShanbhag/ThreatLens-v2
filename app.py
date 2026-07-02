
import ttkbootstrap as tb

from threatlens_gui import ThreatLensGUI

root = tb.Window(
    themename="darkly"
)

app = ThreatLensGUI(root)

root.mainloop()


