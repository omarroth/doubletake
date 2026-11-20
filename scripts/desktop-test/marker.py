#!/usr/bin/python3
"""Draw a timestamp in a native GTK fullscreen window."""
import time

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

window = Gtk.Window()
window.set_title("doubletake desktop capture test")
window.set_decorated(False)
window.set_default_size(640, 360)
window.move(0, 0)
window.connect("destroy", Gtk.main_quit)
canvas = Gtk.DrawingArea()
window.add(canvas)


def draw(widget, cr):
    width, height = widget.get_allocated_width(), widget.get_allocated_height()
    stamp = (time.time_ns() // 1_000_000) & 0xFFFFFF
    # Two calibration bars followed by the 24 bits, most significant first.
    values = [0, 1] + [(stamp >> bit) & 1 for bit in range(23, -1, -1)]
    cr.set_antialias(1)  # Cairo ANTIALIAS_NONE
    for column, value in enumerate(values):
        cr.set_source_rgb(value, value, value)
        cr.rectangle(width * column / len(values), 0, width / len(values), height)
        cr.fill()
    return False


canvas.connect("draw", draw)
window.fullscreen()
window.show_all()


def refresh():
    canvas.queue_draw()
    return True


GLib.timeout_add(33, refresh)
Gtk.main()
