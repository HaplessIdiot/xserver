# hw/xfree86/drivers/video/amdgpu/src/meson.build

amdgpu_srcs = files(
  'amdgpu_bo_helper.c',
  'amdgpu_dri2.c',
  'amdgpu_dri3.c',
  'amdgpu_drm_queue.c',
  'amdgpu_glamor.c',
  'amdgpu_glamor_wrappers.c',
  'amdgpu_kms.c',
  'amdgpu_misc.c',
  'amdgpu_pixmap.c',
  'amdgpu_present.c',
  'amdgpu_probe.c',
  'amdgpu_sync.c',
  'amdgpu_video.c',
  'drmmode_display.c',
)

# Build as a static library instead of a DDX module
amdgpu_static = static_library(
  'amdgpu',
  amdgpu_srcs,
  dependencies: amdgpu_deps,
  include_directories: include_directories('.')
)
