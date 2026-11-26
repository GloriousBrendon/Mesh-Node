//! VST3 plugins through the `vst3` bindings: list, process, editor.

use std::ffi::{CStr, c_void};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use vst3::Steinberg::Linux::{IEventHandlerTrait, ITimerHandlerTrait};
use vst3::Steinberg::Vst::BusDirections_::{kInput, kOutput};
use vst3::Steinberg::Vst::MediaTypes_::kAudio;
use vst3::Steinberg::Vst::ProcessModes_::kRealtime;
use vst3::Steinberg::Vst::SymbolicSampleSizes_::kSample32;
use vst3::Steinberg::Vst::*;
use vst3::Steinberg::*;
use vst3::{Class, ComPtr, ComRef, ComWrapper, Interface};

use crate::{BLOCK, Info, RATE};

/// The library inside a `.vst3` bundle (or the file itself).
fn library_path(bundle: &Path) -> PathBuf {
    if bundle.is_file() {
        return bundle.to_owned();
    }
    let stem = bundle.file_stem().unwrap_or_default();
    #[cfg(target_os = "linux")]
    return bundle
        .join("Contents/x86_64-linux")
        .join(stem)
        .with_extension("so");
    #[cfg(windows)]
    return bundle
        .join("Contents/x86_64-win")
        .join(stem)
        .with_extension("vst3");
}

/// A loaded module: its library and factory. `ModuleExit` runs on drop.
pub struct Module {
    factory: ComPtr<IPluginFactory>,
    lib: libloading::Library,
}

impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: the symbols are the VST3 module API's.
        unsafe {
            #[cfg(target_os = "linux")]
            if let Ok(exit) = self
                .lib
                .get::<unsafe extern "C" fn() -> bool>(b"ModuleExit")
            {
                exit();
            }
            #[cfg(windows)]
            if let Ok(exit) = self
                .lib
                .get::<unsafe extern "system" fn() -> bool>(b"ExitDll")
            {
                exit();
            }
        }
    }
}

pub fn load(path: &str) -> Result<Module, String> {
    let lib_path = library_path(Path::new(path));
    // SAFETY: loading a plugin runs its code; that's why this is its own process (F2).
    unsafe {
        #[cfg(target_os = "linux")]
        let lib: libloading::Library = {
            let l = libloading::os::unix::Library::open(
                Some(&lib_path),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
            .map_err(|e| format!("load {}: {e}", lib_path.display()))?;
            let handle = l.into_raw();
            let l = libloading::os::unix::Library::from_raw(handle);
            if let Ok(entry) = l.get::<unsafe extern "C" fn(*mut c_void) -> bool>(b"ModuleEntry")
                && !entry(handle)
            {
                return Err("ModuleEntry failed".into());
            }
            l.into()
        };
        #[cfg(windows)]
        let lib = {
            let l = libloading::Library::new(&lib_path)
                .map_err(|e| format!("load {}: {e}", lib_path.display()))?;
            if let Ok(init) = l.get::<unsafe extern "system" fn() -> bool>(b"InitDll") {
                init();
            }
            l
        };
        let get = lib
            .get::<unsafe extern "system" fn() -> *mut IPluginFactory>(b"GetPluginFactory")
            .map_err(|e| format!("GetPluginFactory: {e}"))?;
        let factory = ComPtr::from_raw(get()).ok_or("no plugin factory")?;
        Ok(Module { factory, lib })
    }
}

fn c_text(chars: &[i8]) -> String {
    // SAFETY: the SDK's fixed-size strings are NUL-terminated.
    unsafe { CStr::from_ptr(chars.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned()
}

fn hex(cid: &TUID) -> String {
    cid.iter().map(|b| format!("{:02X}", *b as u8)).collect()
}

fn unhex(s: &str) -> Option<TUID> {
    let mut out = [0i8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()? as i8;
    }
    Some(out)
}

/// The audio effects in `path`; the id is the class ID in hex.
pub fn list(path: &str) -> Result<Vec<Info>, String> {
    let m = load(path)?;
    let mut factory_info: PFactoryInfo = unsafe { std::mem::zeroed() };
    let vendor = if unsafe { m.factory.getFactoryInfo(&mut factory_info) } == kResultOk {
        c_text(&factory_info.vendor)
    } else {
        String::new()
    };
    let mut out = Vec::new();
    for i in 0..unsafe { m.factory.countClasses() } {
        let mut info: PClassInfo = unsafe { std::mem::zeroed() };
        if unsafe { m.factory.getClassInfo(i, &mut info) } == kResultOk
            && c_text(&info.category) == "Audio Module Class"
        {
            out.push(Info {
                id: hex(&info.cid),
                name: c_text(&info.name),
                vendor: vendor.clone(),
            });
        }
    }
    Ok(out)
}

// --- What we give the plugin ---

struct HostApp;

impl Class for HostApp {
    type Interfaces = (IHostApplication,);
}

impl IHostApplicationTrait for HostApp {
    unsafe fn getName(&self, name: *mut String128) -> tresult {
        let name = unsafe { &mut *name };
        for (d, s) in name.iter_mut().zip("Aflos".encode_utf16().chain([0])) {
            *d = s as TChar;
        }
        kResultOk
    }

    unsafe fn createInstance(
        &self,
        _cid: *mut TUID,
        _iid: *mut TUID,
        obj: *mut *mut c_void,
    ) -> tresult {
        // ponytail: no IMessage/IAttributeList yet; plugins that talk processor-to-editor through them may want it (Task 5).
        unsafe { *obj = ptr::null_mut() };
        kNotImplemented
    }
}

struct Handler;

impl Class for Handler {
    type Interfaces = (IComponentHandler,);
}

impl IComponentHandlerTrait for Handler {
    unsafe fn beginEdit(&self, _id: ParamID) -> tresult {
        kResultOk
    }
    unsafe fn performEdit(&self, _id: ParamID, _value: ParamValue) -> tresult {
        kResultOk
    }
    unsafe fn endEdit(&self, _id: ParamID) -> tresult {
        kResultOk
    }
    unsafe fn restartComponent(&self, _flags: int32) -> tresult {
        kResultOk
    }
}

/// The editor's frame; on Linux also the run loop the editor drives its UI with.
#[derive(Default)]
struct Frame {
    #[cfg(target_os = "linux")]
    fds: Mutex<Vec<(ComPtr<Linux::IEventHandler>, i32)>>,
    #[cfg(target_os = "linux")]
    timers: Mutex<Vec<(ComPtr<Linux::ITimerHandler>, Duration, Instant)>>,
}

#[cfg(target_os = "linux")]
impl Class for Frame {
    type Interfaces = (IPlugFrame, Linux::IRunLoop);
}
#[cfg(not(target_os = "linux"))]
impl Class for Frame {
    type Interfaces = (IPlugFrame,);
}

impl IPlugFrameTrait for Frame {
    unsafe fn resizeView(&self, view: *mut IPlugView, size: *mut ViewRect) -> tresult {
        // ponytail: the parent window isn't resized yet; fine for fixed-size editors.
        match unsafe { ComRef::from_raw(view) } {
            Some(v) => unsafe { v.onSize(size) },
            None => kInvalidArgument,
        }
    }
}

#[cfg(target_os = "linux")]
impl Linux::IRunLoopTrait for Frame {
    unsafe fn registerEventHandler(
        &self,
        handler: *mut Linux::IEventHandler,
        fd: Linux::FileDescriptor,
    ) -> tresult {
        let Some(h) = (unsafe { ComRef::from_raw(handler) }) else {
            return kInvalidArgument;
        };
        self.fds.lock().unwrap().push((h.to_com_ptr(), fd));
        kResultOk
    }
    unsafe fn unregisterEventHandler(&self, handler: *mut Linux::IEventHandler) -> tresult {
        self.fds
            .lock()
            .unwrap()
            .retain(|(h, _)| h.as_ptr() != handler);
        kResultOk
    }
    unsafe fn registerTimer(
        &self,
        handler: *mut Linux::ITimerHandler,
        ms: Linux::TimerInterval,
    ) -> tresult {
        let Some(h) = (unsafe { ComRef::from_raw(handler) }) else {
            return kInvalidArgument;
        };
        let period = Duration::from_millis(ms.max(15));
        self.timers
            .lock()
            .unwrap()
            .push((h.to_com_ptr(), period, Instant::now()));
        kResultOk
    }
    unsafe fn unregisterTimer(&self, handler: *mut Linux::ITimerHandler) -> tresult {
        self.timers
            .lock()
            .unwrap()
            .retain(|(h, ..)| h.as_ptr() != handler);
        kResultOk
    }
}

#[cfg(target_os = "linux")]
impl Frame {
    /// Calls handlers whose fd is readable and timers that are due; how many.
    fn pump(&self) -> (u32, u32) {
        let fds: Vec<_> = self
            .fds
            .lock()
            .unwrap()
            .iter()
            .map(|(h, fd)| (h.clone(), *fd))
            .collect();
        let mut polls: Vec<libc::pollfd> = fds
            .iter()
            .map(|(_, fd)| libc::pollfd {
                fd: *fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `polls` is a valid array of its length.
        unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 0) };
        let mut fired = 0;
        for ((h, fd), p) in fds.iter().zip(&polls) {
            if p.revents != 0 {
                unsafe { h.onFDIsSet(*fd) };
                fired += 1;
            }
        }
        let now = Instant::now();
        let due: Vec<_> = self
            .timers
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|(_, p, last)| now.duration_since(*last) >= *p)
            .map(|(h, _, last)| {
                *last = now;
                h.clone()
            })
            .collect();
        for h in &due {
            unsafe { h.onTimer() };
        }
        (fired, due.len() as u32)
    }
}

// --- An instance ---

/// A block per channel, per bus.
type Buses = Vec<Vec<Vec<f32>>>;

pub struct Instance {
    component: ComPtr<IComponent>,
    processor: ComPtr<IAudioProcessor>,
    controller: Option<ComPtr<IEditController>>,
    /// Whether the controller is its own object (initialised and terminated by us).
    separate: bool,
    points: Option<(ComPtr<IConnectionPoint>, ComPtr<IConnectionPoint>)>,
    host: ComWrapper<HostApp>,
    _handler: ComWrapper<Handler>,
    /// Channels per bus, inputs then outputs.
    buses: (Vec<usize>, Vec<usize>),
    /// Input and output buffers while processing.
    running: Option<(Buses, Buses)>,
    _module: Module,
}

fn create<I: Interface>(m: &Module, cid: &TUID) -> Option<ComPtr<I>> {
    let mut obj = ptr::null_mut();
    let iid = I::IID;
    let ok = unsafe {
        m.factory
            .createInstance(cid.as_ptr(), iid.as_ptr().cast(), &mut obj)
    };
    if ok != kResultOk {
        return None;
    }
    unsafe { ComPtr::from_raw(obj.cast()) }
}

pub fn open(path: &str, id: &str) -> Result<Instance, String> {
    let module = load(path)?;
    let cid = unhex(id).ok_or("bad class id")?;
    let host = ComWrapper::new(HostApp);
    let host_unknown = host.to_com_ptr::<FUnknown>().unwrap();
    let component: ComPtr<IComponent> =
        create(&module, &cid).ok_or("createInstance(IComponent) failed")?;
    if unsafe { component.initialize(host_unknown.as_ptr()) } != kResultOk {
        return Err("component initialize failed".into());
    }
    let processor = component
        .cast::<IAudioProcessor>()
        .ok_or("no IAudioProcessor")?;
    let (controller, separate) = match component.cast::<IEditController>() {
        Some(c) => (Some(c), false),
        None => {
            let mut ccid: TUID = [0; 16];
            let c = (unsafe { component.getControllerClassId(&mut ccid) } == kResultOk)
                .then(|| create::<IEditController>(&module, &ccid))
                .flatten();
            if let Some(c) = &c {
                unsafe { c.initialize(host_unknown.as_ptr()) };
            }
            (c, true)
        }
    };
    let handler = ComWrapper::new(Handler);
    let mut points = None;
    if let Some(c) = &controller {
        unsafe {
            c.setComponentHandler(handler.to_com_ptr::<IComponentHandler>().unwrap().as_ptr())
        };
        if separate
            && let (Some(a), Some(b)) = (
                component.cast::<IConnectionPoint>(),
                c.cast::<IConnectionPoint>(),
            )
        {
            unsafe {
                a.connect(b.as_ptr());
                b.connect(a.as_ptr());
            }
            points = Some((a, b));
        }
    }
    // Mono in, mono out if it takes it (F7); otherwise what it has.
    let ins = unsafe { component.getBusCount(kAudio as i32, kInput as i32) };
    let outs = unsafe { component.getBusCount(kAudio as i32, kOutput as i32) };
    let mut mono_in = vec![SpeakerArr::kMono; ins.max(0) as usize];
    let mut mono_out = vec![SpeakerArr::kMono; outs.max(0) as usize];
    unsafe { processor.setBusArrangements(mono_in.as_mut_ptr(), ins, mono_out.as_mut_ptr(), outs) };
    let channels = |dir, n: i32| -> Vec<usize> {
        (0..n)
            .map(|i| {
                let mut info: BusInfo = unsafe { std::mem::zeroed() };
                unsafe { component.getBusInfo(kAudio as i32, dir, i, &mut info) };
                // Only the main bus on; sidechains stay off.
                unsafe { component.activateBus(kAudio as i32, dir, i, u8::from(i == 0)) };
                info.channelCount.max(0) as usize
            })
            .collect()
    };
    let buses = (channels(kInput as i32, ins), channels(kOutput as i32, outs));
    Ok(Instance {
        component,
        processor,
        controller,
        separate,
        points,
        host,
        _handler: handler,
        buses,
        running: None,
        _module: module,
    })
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.stop();
        unsafe {
            if let Some((a, b)) = &self.points {
                a.disconnect(b.as_ptr());
                b.disconnect(a.as_ptr());
            }
            if self.separate
                && let Some(c) = &self.controller
            {
                c.terminate();
            }
            self.component.terminate();
        }
        let _ = &self.host;
    }
}

impl Instance {
    pub fn latency(&self) -> u32 {
        unsafe { self.processor.getLatencySamples() }
    }

    /// Sets it up for 960-frame blocks at 48 kHz and starts processing.
    pub fn start(&mut self) -> Result<(), String> {
        if self.running.is_some() {
            return Ok(());
        }
        let mut setup = ProcessSetup {
            processMode: kRealtime as i32,
            symbolicSampleSize: kSample32 as i32,
            maxSamplesPerBlock: BLOCK as i32,
            sampleRate: f64::from(RATE),
        };
        unsafe {
            if self.processor.setupProcessing(&mut setup) != kResultOk {
                return Err("setupProcessing failed".into());
            }
            self.component.setActive(1);
            self.processor.setProcessing(1);
        }
        let bufs = |chans: &[usize]| chans.iter().map(|&n| vec![vec![0f32; BLOCK]; n]).collect();
        self.running = Some((bufs(&self.buses.0), bufs(&self.buses.1)));
        Ok(())
    }

    /// One block through it, in place: mono in on the main bus's channels,
    /// its main output averaged back to mono (F7).
    pub fn block(&mut self, buf: &mut [f32; BLOCK]) -> Result<(), String> {
        let (in_data, out_data) = self.running.as_mut().ok_or("not started")?;
        if let Some(main) = in_data.first_mut() {
            for ch in main.iter_mut() {
                ch.copy_from_slice(buf);
            }
        }
        let mut in_ptrs: Vec<Vec<*mut f32>> = in_data
            .iter_mut()
            .map(|b| b.iter_mut().map(|c| c.as_mut_ptr()).collect())
            .collect();
        let mut out_ptrs: Vec<Vec<*mut f32>> = out_data
            .iter_mut()
            .map(|b| b.iter_mut().map(|c| c.as_mut_ptr()).collect())
            .collect();
        let bus = |p: &mut Vec<*mut f32>| AudioBusBuffers {
            numChannels: p.len() as i32,
            silenceFlags: 0,
            __field0: AudioBusBuffers__type0 {
                channelBuffers32: p.as_mut_ptr(),
            },
        };
        let mut in_bufs: Vec<AudioBusBuffers> = in_ptrs.iter_mut().map(bus).collect();
        let mut out_bufs: Vec<AudioBusBuffers> = out_ptrs.iter_mut().map(bus).collect();
        let mut data = ProcessData {
            processMode: kRealtime as i32,
            symbolicSampleSize: kSample32 as i32,
            numSamples: BLOCK as i32,
            numInputs: in_bufs.len() as i32,
            numOutputs: out_bufs.len() as i32,
            inputs: in_bufs.as_mut_ptr(),
            outputs: out_bufs.as_mut_ptr(),
            inputParameterChanges: ptr::null_mut(),
            outputParameterChanges: ptr::null_mut(),
            inputEvents: ptr::null_mut(),
            outputEvents: ptr::null_mut(),
            processContext: ptr::null_mut(),
        };
        let r = unsafe { self.processor.process(&mut data) };
        if r != kResultOk {
            return Err(format!("process returned {r}"));
        }
        let main = out_data.first().ok_or("no output bus")?;
        let n = main.len().max(1) as f32;
        for (i, s) in buf.iter_mut().enumerate() {
            *s = main.iter().map(|c| c[i]).sum::<f32>() / n;
        }
        Ok(())
    }

    /// Stops processing and deactivates it.
    pub fn stop(&mut self) {
        if self.running.take().is_some() {
            unsafe {
                self.processor.setProcessing(0);
                self.component.setActive(0);
            }
        }
    }

    /// Runs `input` (mono) through it in 960-frame blocks; mono out, block times.
    pub fn process(&mut self, input: &[f32]) -> Result<(Vec<f32>, Vec<Duration>), String> {
        self.start()?;
        let (mut out, mut times) = (Vec::with_capacity(input.len()), Vec::new());
        for block in input.as_chunks::<BLOCK>().0 {
            let mut buf = *block;
            let started = Instant::now();
            self.block(&mut buf)?;
            times.push(started.elapsed());
            out.extend(buf);
        }
        self.stop();
        Ok((out, times))
    }

    /// Opens its editor for `secs`, embedded in an X11 window, pumping its run loop.
    #[cfg(target_os = "linux")]
    pub fn edit(&mut self, secs: u64) -> Result<String, String> {
        let c = self.controller.as_ref().ok_or("no edit controller")?;
        let view = unsafe { ComPtr::from_raw(c.createView(c"editor".as_ptr())) }
            .ok_or("no editor view")?;
        if unsafe { view.isPlatformTypeSupported(kPlatformTypeX11EmbedWindowID) } != kResultOk {
            return Err("editor doesn't support X11 embedding".into());
        }
        let frame = ComWrapper::new(Frame::default());
        unsafe { view.setFrame(frame.to_com_ptr::<IPlugFrame>().unwrap().as_ptr()) };
        let mut rect = ViewRect {
            left: 0,
            top: 0,
            right: 800,
            bottom: 500,
        };
        unsafe { view.getSize(&mut rect) };
        let (w, h) = (
            (rect.right - rect.left).max(1),
            (rect.bottom - rect.top).max(1),
        );
        let parent = crate::x11::Parent::new(w as u16, h as u16)?;
        if unsafe {
            view.attached(
                parent.id as usize as *mut c_void,
                kPlatformTypeX11EmbedWindowID,
            )
        } != kResultOk
        {
            return Err("attached failed".into());
        }
        let until = Instant::now() + Duration::from_secs(secs);
        let (mut fds, mut ticks) = (0, 0);
        while Instant::now() < until {
            let (f, t) = frame.pump();
            fds += f;
            ticks += t;
            parent.pump();
            std::thread::sleep(Duration::from_millis(5));
        }
        let handlers = (
            frame.fds.lock().unwrap().len(),
            frame.timers.lock().unwrap().len(),
        );
        unsafe {
            view.removed();
            view.setFrame(ptr::null_mut());
        }
        Ok(format!(
            "embedded editor {w}x{h}, run loop: {} fd handlers, {} timers, {fds} fd events, {ticks} timer ticks",
            handlers.0, handlers.1
        ))
    }
}
