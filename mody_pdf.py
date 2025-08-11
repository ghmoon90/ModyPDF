"""
tk_pdf_image_manager.py

A single-file Tkinter application that:
1. Reads images and PDF files (multi-file) using a file dialog
2. Shows each PDF page and image as a separate "page" in a list
3. Allows multi-selection, deselection, and deleting selected pages
4. Move Up/Down buttons: when moving, the LAST selected page is the one that moves,
   and all other selections are cleared (as requested)
5. Exports the current page order into a single PDF
6. Optionally encrypts the final PDF with a password

Dependencies (install with pip):
    pip install PyMuPDF Pillow PyPDF2

Notes:
- PyMuPDF (fitz) is used to read PDFs and render thumbnails.
- PyPDF2 is used to assemble and encrypt the final PDF.
- Images are converted to single-page PDFs via Pillow and merged via PyPDF2.

"""



import io
import os
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox
from dataclasses import dataclass
from typing import List

import fitz  # PyMuPDF
from PIL import Image, ImageTk
from PyPDF2 import PdfReader, PdfWriter

THUMB_W = 160
THUMB_H = 120

@dataclass
class PageItem:
    src_path: str            # original file path
    src_type: str            # 'pdf' or 'image'
    pdf_page_index: int      # for pdf pages: page index in source pdf (0-based). for images: -1
    label: str               # display label
    thumb: ImageTk.PhotoImage
    pil_image: Image.Image   # original image (for image pages) or None
    # for PDFs we keep no PIL image, but we keep reference to src_path and page index

iconhex = "32,32\n#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#01000000#00000000#005f1720#04943b3c#00671720#00000000#00ff0001#007f0002#00ff0001#00000000#00000000#00000000#00000000#00000000#00000001#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00ff0001#ffffff01#0033000f#21b14ba8#50e56bf1#58ee70fd#4ee26cf0#2ab64e78#01000000#02000000#01000000#7fff7f02#00000000#7fff7f02#7fff7f04#ffffff01#02010100#ffffff01#3fbf3f04#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#3fff7f04#00000000#21ad49a9#6bff83ff#65fe7bff#62fa78fe#76ff85ff#59f473ff#00792a2a#0051121c#00470a19#00000000#ffffff01#00000000#00000000#00000000#00000003#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#55ff5503#7fff7f04#3fff7f04#00bf3f04#00000000#067c2d27#56ee70ff#4be46ffb#04a14afe#08a74dff#33cf62fe#69ff7cfe#3bcc5de0#4de168f3#47db67f1#1fad498a#00000000#2cb75039#44d66592#48dc66c9#44d963d9#3cd05fc5#1fad4a71#00000003#00ff0001#00000001#00000000#00000000#00000000#00000000#00000000#00010000#00000000#00000000#00000000#00000000#149a4326#1dae474f#64fd79fb#11b252fe#009d48ff#00a34bff#009946ff#31ce61ff#74ff83ff#65ff7bff#73ff84ff#53ea6eff#4bdd66c3#6aff7cff#72ff85ff#73ff84ff#71ff82ff#6eff81ff#62ff7dff#24b04c78#00000000#3fbf3f04#00000000#00000000#00000000#00000000#ffff0001#00000000#1ca84661#45d966a2#48d86678#05792c2e#4bdf68e3#59eb71f1#60f775f9#0aad50ff#00a14aff#02a44bff#01a24bff#05a74dff#3ad665fd#09a64dfe#22c05afe#6dff7dfe#58f977ff#2bc75eff#1bb956fb#25c15afd#50e96ffd#67ff79f9#71ff86fd#31c256bf#00000001#55ffaa03#00000000#00000000#00000000#00aa5503#00000000#139b3e4d#58f875ff#76ff87ff#72ff85ff#5ef374f6#57eb6ef3#57ef75ff#2cc95fff#06a84dff#00a24aff#00a34bff#00a34bff#01a44cff#00a24bff#00a24aff#009c47ff#21c05aff#04a54cfc#009a47ff#009f49ff#009846ff#0bac50ff#6aff7dfc#49e369f9#098b3654#01000000#00aa5503#00000000#00000000#00000000#3fff7f04#00000000#30c1569d#70ff84fc#3ad766f7#1fb956fb#34d264ff#61f778ff#30cc60fe#009644ff#02a44cff#00a34bff#00a34bff#00a24bff#00a14aff#009f49ff#009d48ff#0dae51ff#05a74dff#009e48ff#02a54cff#03a54cff#029f49ff#39d565fe#69fc7afe#29b74ff1#18a74474#002e000b#00000000#00ff0001#00000000#00000000#3fff7f04#00000000#3bce5c9a#66ff81ff#009f49fb#009e48ff#009543fe#26c55cfe#4ce66eff#019f49ff#01a44bff#00a34bff#01a34bff#04a54cff#2bc85eff#43de69ff#3dd566ff#5ef576ff#4ce46eff#21be59ff#00a049ff#01a34bff#03a54cff#1dbc58ff#1fbb58ff#4de86ffe#69ff81ff#33c456b3#00000003#7fff7f02#00000000#00000000#00aa5503#ffffff01#25a14429#45dd66f0#0fb152fe#009c47fe#10b052ff#41dc69ff#13b052ff#00a24bff#00a34bff#00a34bff#00a34bff#03a54cff#08a74dff#1ebd58ff#5ff477ff#16b755ff#01a14aff#1cbb58ff#02a34bff#00a34bff#00a34bff#009e49ff#009e49ff#2fcb5ffd#7aff88ff#42d662fc#0012000e#01000000#00ff0001#00000001#00000000#00000000#098d3836#3ccb5ac5#53ed71ff#08a64cfd#15b655ff#20bf5aff#009946ff#01a44cff#00a34bff#00a34bff#00a34bff#00a24bff#00a24aff#009e49ff#02a54cff#00a04aff#00a34bff#009f49ff#00a34bff#00a34bff#01a44cff#01a04aff#26c45cfe#67fc7afd#43d663eb#19a14270#00000001#7f7f7f02#00000000#7fff7f02#00552a06#36c558a4#59f275ff#36d566ff#27c15cff#0cae51ff#01a34bff#17b655ff#01a34bff#00a34bff#00a34bff#00a34bff#00a34bff#00a34bff#00a34bff#01a34bff#00a24bff#01a44bff#00a34bff#01a44bff#00a34bff#00a34bff#00a34bff#00a34bff#00a049fd#11b554ff#22b54dd0#002e000b#55aa5503#00ff0001#00000000#00000000#00722826#5dfd77ff#65fd7bfe#00a04afe#009b47ff#00a14aff#00a34bff#00a24bff#00a34bff#00a34bff#00a34bff#00a34bff#00a34bff#00a54cff#00a34bff#00a54cff#00a44cff#00a24bff#00a34bff#00a34bff#00a34bff#00a34bff#00a34bff#00a34bff#00a14aff#07a94efb#64ff80ff#2ab84f8a#01000000#33cc6605#00000000#7fff7f02#003f0004#2ebd54aa#69fb7dff#3cda67fc#02a04aff#01a44bff#00a34bff#00a34bff#00a34bff#00a34bff#00a24aff#00a24aff#00a44bff#019b46ff#01a34bff#079947ff#2d7d41ff#00a84dff#01a24bff#00a34bff#00a34bff#00a34bff#00a34bff#01a34bff#03a14aff#42de6afc#5eef74fd#2bbb52bc#004d1617#01010100#00ff0001#ffffff01#005f1f10#4fe469d5#49e66fff#06a34bfd#01a34bff#00a44cff#00a44bff#00a44bff#00a54cff#00a34bff#00a24bff#009543ff#009241ff#03843aff#008a3aff#426638ff#316a36ff#009340ff#029c48ff#00a34bff#00a34bff#00a54cff#00a34bff#00a44cff#01a44bff#07a64cff#2bc75dfd#6aff80ff#36c859d6#0027000d#ffffff01#00000000#27b54e61#6bff82ff#0eb050fc#009d48ff#03a64dff#009e48ff#00a049ff#00a14aff#009945ff#00a54cff#00a54cff#00a14aff#01a24bff#019944ff#167d39ff#8b6744ff#0a873dff#009744ff#019f49ff#00a84dff#00a049ff#009945ff#00a44cff#009a46ff#00a14aff#00a34bff#009845ff#33d162fa#6aff80ff#16a14165#00000000#00000000#39cb5c9a#74ff86fa#30ce61f7#009845fe#009f49ff#009c47ff#01853aff#01873bff#018238ff#028a3dff#029342ff#00a24aff#02a64dff#009540ff#707a48ff#95764dff#009643ff#01a84eff#028a3dff#028b3eff#02883cff#01873bff#01853aff#018b3dff#01a44bff#02a74dff#009a46ff#35d263f9#74ff87fd#27b65094#00000000#00000000#2ebd537d#69ff82ff#70ff83ff#4fee72ff#3bd364ff#11ad50ff#019e48ff#02a24aff#009e48ff#009743ff#00a249ff#03a64dff#01a54cff#0b7b37ff#bd855aff#837b4cff#029744ff#05a74eff#009d47ff#009541ff#009f48ff#00a24aff#009945ff#00a34bff#00a14aff#009544ff#2dc55dfb#73ff84ff#4be269ff#10923a3d#01000000#00ff0001#00240007#29b94f76#44d865b3#47d863e2#59ee70fd#03893cfe#009644ff#009040ff#00a149ff#1b994bff#1d8f46ff#009542ff#009b43ff#42743eff#d0875dff#7b7548ff#009a43ff#00a148ff#089c49ff#328a48ff#238844ff#01a44bff#01a54cff#019040ff#129a46ff#33c159ff#4de36aff#2cbc54e6#03853354#00000000#007f7f02#00000000#00000000#00000000#00000000#28b85098#6dff84ff#28b251f9#149543ff#1a9c47ff#038b3cff#187d3aff#a87a52ff#877a4cff#127434ff#697545ff#cc855aff#857248ff#1e7538ff#71824cff#9a744dff#46723eff#0a9d49ff#02a74dff#02a94eff#01893cfe#2ab352ff#30c256e1#006e2258#00280013#00000000#007f7f02#00000000#00000000#00000001#2ad45506#aaffaa03#26aa483c#4de26be7#66ff7cff#5bf173ff#51e66cff#08873cff#008336ff#4b7d43ff#d3875dff#a37b51ff#a68356ff#b57d51ff#be8e5fff#bc8459ff#ca895eff#2d763aff#008d3cff#008c3eff#008f40ff#009342ff#008339fe#007230fc#42d964fa#3bcf5e56#02000000#2aaa5506#00000000#00000000#00000000#00000000#00000000#00ff0001#00000000#005d0d13#1fb04a41#2cbb52d0#56eb71ff#04853afd#007f36ff#057534fd#9e754dfe#b2774dff#c08a5bff#a9744bff#b48154ff#c28257ff#5a7141fd#007e33fd#027e37ff#08893dff#23ab4dff#0f9241ff#129443ff#29b252fa#6eff85ff#34c457a1#00ff0001#3fff7f04#00000000#00000000#00000000#00000000#00000000#00000000#007f7f02#03010100#00000000#44d663d8#77ff87fc#33bf59f9#0d8b3dfb#14a348ff#868952ff#b1714bff#a7744bff#ae794fff#a06c45ff#c3845aff#509f52ff#0f9a44ff#058137fb#37c45bfd#67fd7afd#31c055f4#4ede68f6#5df776ff#42d663e0#0b88352b#00000001#007f0002#00000000#00000000#00000000#00000000#00000000#00000000#00000000#3fbf7f04#55aa5503#28b64f97#65ff80ff#70ff83ff#6bff81ff#3ddc62d4#907c4ec2#bd8256ff#b27e52fd#b58054ff#ad7a4ffe#c48a5dfe#79a15893#47e56ade#65ff7dff#6fff81ff#74ff88ff#37c95ad0#00671f20#04963b38#0022000f#00000000#00000001#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000001#00000001#00000007#22b24c68#38cc5e8d#33c4586d#00350013#a9724fc8#ba8455ff#b98457fc#bb8759ff#b17b50fb#c79361ff#944a3c5d#00842819#37c5599c#42d561d8#40d261d6#1fad4851#01000000#00000000#01000000#007f0002#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#01000000#00000000#00000000#00000000#6635293e#be8e5ffe#bd8858f9#b48054fe#bd895aff#a56f48fb#cb9462ff#956e49a9#00000000#00000000#00000004#00000002#00000000#007f0002#00ff7f02#00ff0001#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#66996605#00030100#1122110f#a87a52db#c48b5cff#b0794fff#ad774dfe#996542ff#a56f48ff#bd8657ff#bc8a5bf2#6a48304a#00000000#02010100#02010100#00ff7f02#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#7f000002#00000000#6a463124#996a49d7#a6744ffd#7a4d36c5#784c35ab#986343ff#996544fe#7d5038ee#88573afb#b17a52ff#af7d55ff#754c3589#55381c09#7f7f7f02#00000001#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000001#ff000001#754e3a0d#734b3484#9466456e#4d261e21#00000000#00000000#7a4c3864#9b6445ff#7d4f38ad#5c362e21#663e2d5a#8a5d4188#7e533abb#6e443168#7f7f0002#7f7f0002#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#7f3f3f04#00000000#00000000#00000000#ffff0001#99663305#00000000#7c50375c#805138f2#7f4f2f10#00000000#00000000#00000000#7f3f3f04#00000001#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#7f7f3f04#7f7f0002#00000000#00000000#7f3f3f04#00000000#774a334f#734a3363#7f3f3f04#91484807#aa555503#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#aa555503#00000000#754e270d#00000001#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000#00000000"


class App:
    def __init__(self, root):
        self.root = root
        root.title('PDF/Image Page Manager')
        self.pages: List[PageItem] = []

        # Top controls
        toolbar = ttk.Frame(root)
        toolbar.pack(side='top', fill='x')

        ttk.Button(toolbar, text='Open files', command=self.open_files).pack(side='left', padx=4, pady=4)
        ttk.Button(toolbar, text='Delete selected', command=self.delete_selected).pack(side='left', padx=4)
        ttk.Button(toolbar, text='Move Up', command=lambda: self.move_selected(-1)).pack(side='left', padx=4)
        ttk.Button(toolbar, text='Move Down', command=lambda: self.move_selected(1)).pack(side='left', padx=4)
        ttk.Button(toolbar, text='Export PDF', command=self.export_pdf).pack(side='left', padx=4)

        # Middle: list of pages with thumbnails
        body = ttk.Frame(root)
        body.pack(side='top', fill='both', expand=True)

        self.canvas = tk.Canvas(body)
        self.scroll = ttk.Scrollbar(body, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scroll.set)
        self.scroll.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)

        self.inner = ttk.Frame(self.canvas)
        self.canvas.create_window((0,0), window=self.inner, anchor='nw')
        self.inner.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))

        # We'll maintain a list of Checkbuttons + thumbnail labels so multi-select is possible
        self.item_vars: List[tk.IntVar] = []
        self.item_widgets: List[ttk.Frame] = []

        # Bindings for selection semantics: support click to select/deselect and shift/ctrl with default system behavior
        root.bind('<Delete>', lambda e: self.delete_selected())

    def open_files(self):
        paths = filedialog.askopenfilenames(title='Select images or PDFs', filetypes=[('PDF', '*.pdf'),
                                                                                        ('Images', '*.png;*.jpg;*.jpeg;*.bmp;*.tiff'),
                                                                                        ('All files', '*.*')])
        if not paths:
            return
        for p in paths:
            p = os.fspath(p)
            ext = os.path.splitext(p)[1].lower()
            try:
                if ext == '.pdf':
                    self._append_pdf(p)
                else:
                    self._append_image(p)
            except Exception as e:
                messagebox.showerror('Error', f'Failed to open {p}: {e}')
        self._render_list()

    def _append_pdf(self, path):
        doc = fitz.open(path)
        for i in range(len(doc)):
            page = doc.load_page(i)
            mat = fitz.Matrix( (THUMB_W / page.rect.width), (THUMB_H / page.rect.height) )
            pix = page.get_pixmap(matrix=mat, alpha=False)
            img = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
            thumb = ImageTk.PhotoImage(img)
            label = f"{os.path.basename(path)} — page {i+1}"
            self.pages.append(PageItem(src_path=path, src_type='pdf', pdf_page_index=i, label=label, thumb=thumb, pil_image=None))
        doc.close()

    def _append_image(self, path):
        pil = Image.open(path).convert('RGB')
        # make thumbnail copy
        img = pil.copy()
        img.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
        thumb = ImageTk.PhotoImage(img)
        label = f"{os.path.basename(path)}"
        self.pages.append(PageItem(src_path=path, src_type='image', pdf_page_index=-1, label=label, thumb=thumb, pil_image=pil))

    def _clear_item_widgets(self):
        for w in self.item_widgets:
            w.destroy()
        self.item_widgets.clear()
        self.item_vars.clear()

    def _render_list(self):
        self._clear_item_widgets()
        for idx, page in enumerate(self.pages):
            frame = ttk.Frame(self.inner, relief='ridge', padding=4)
            frame.grid(row=idx, column=0, sticky='we', pady=2, padx=2)
            frame.columnconfigure(1, weight=1)

            var = tk.IntVar(value=0)
            chk = ttk.Checkbutton(frame, variable=var, command=lambda i=idx: self._on_check_clicked(i))
            chk.grid(row=0, column=0, rowspan=2, sticky='n')

            lbl_img = tk.Label(frame, image=page.thumb)
            lbl_img.image = page.thumb
            lbl_img.grid(row=0, column=1, sticky='w')

            lbl_text = ttk.Label(frame, text=page.label)
            lbl_text.grid(row=1, column=1, sticky='w')

            # Click on frame selects the checkbox (supports deselect when clicking again)
            def on_frame_click(ev, i=idx):
                # Toggle checkbox
                current = self.item_vars[i].get()
                newv = 0 if current else 1
                # Clear other selections if shift not held? We'll rely on ctrl/shift of OS for multiple selects.
                self.item_vars[i].set(newv)
            frame.bind('<Button-1>', on_frame_click)
            lbl_img.bind('<Button-1>', on_frame_click)
            lbl_text.bind('<Button-1>', on_frame_click)

            self.item_vars.append(var)
            self.item_widgets.append(frame)

    def _on_check_clicked(self, idx):
        # nothing special now; selection state maintained in item_vars
        pass

    def get_selected_indices(self):
        return [i for i,v in enumerate(self.item_vars) if v.get()==1]

    def delete_selected(self):
        sel = self.get_selected_indices()
        if not sel:
            messagebox.showinfo('Delete', 'No pages selected')
            return
        if not messagebox.askyesno('Confirm', f'Delete {len(sel)} selected page(s)?'):
            return
        # delete by creating new list skipping those indices
        new_pages = [p for i,p in enumerate(self.pages) if i not in sel]
        self.pages = new_pages
        self._render_list()

    def move_selected(self, direction: int):
        """Move the last selected page up (direction=-1) or down (direction=1).
        After move, *other* selections are cleared and the moved page becomes selected.
        """
        sel = self.get_selected_indices()
        if not sel:
            messagebox.showinfo('Move', 'No pages selected')
            return
        last = sel[-1]
        new_index = last + direction
        if new_index < 0 or new_index >= len(self.pages):
            return
        # perform swap to move the page by one
        self.pages.insert(new_index, self.pages.pop(last))
        # re-render
        self._render_list()
        # set selection: only the moved page
        for i,v in enumerate(self.item_vars):
            v.set(1 if i==new_index else 0)

    def export_pdf(self):
        if not self.pages:
            messagebox.showinfo('Export', 'No pages to export')
            return
        out_path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF','*.pdf')])
        if not out_path:
            return
        # ask whether to encrypt
        do_encrypt = messagebox.askyesno('Encrypt', 'Encrypt the exported PDF with a password?')
        password = None
        if do_encrypt:
            password = simpledialog.askstring('Password', 'Enter PDF password:', show='*')
            if password is None:
                return

        writer = PdfWriter()

        try:
            for page in self.pages:
                if page.src_type == 'pdf':
                    # read specific page from original pdf
                    reader = PdfReader(page.src_path)
                    # safety: ensure page index in range
                    if page.pdf_page_index < 0 or page.pdf_page_index >= len(reader.pages):
                        raise RuntimeError('PDF page index out of range')
                    writer.add_page(reader.pages[page.pdf_page_index])
                else:
                    # image -> single page pdf via PIL to bytes
                    buf = io.BytesIO()
                    page.pil_image.save(buf, format='PDF')
                    buf.seek(0)
                    img_reader = PdfReader(buf)
                    # append all pages (should be 1)
                    for p in img_reader.pages:
                        writer.add_page(p)
            if password:
                writer.encrypt(user_pwd=password, owner_pwd=None, use_128bit=True)
            # write out
            with open(out_path, 'wb') as f:
                writer.write(f)
            messagebox.showinfo('Exported', f'Wrote {out_path}')
        except Exception as e:
            messagebox.showerror('Export error', str(e))


if __name__ == '__main__':
    
    parts = iconhex.split('\n')
    dimensions = parts[0].split(',')
    width = int(dimensions[0])
    height = int(dimensions[1])
    hex_pixels = parts[1].replace('#', '')
    pixels = []
    for i in range(0, len(hex_pixels), 8):
        pixels.append(tuple(int(hex_pixels[i:i+8][j:j+2], 16) for j in range(0, 8, 2)))

    image = Image.new('RGBA', (width, height))
    image.putdata(pixels)
   
    
    root = tk.Tk()
    app = App(root)
    root.geometry('700x560')
    tk_image = ImageTk.PhotoImage(image)
    root.iconphoto(True, tk_image) 
    root.mainloop()
