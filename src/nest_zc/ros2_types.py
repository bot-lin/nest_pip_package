from dataclasses import dataclass
from pycdr2 import IdlStruct
from pycdr2.types import float64, int32, uint32, float32, int8, uint8, sequence, int64, uint16, int16
import pycdr2

from typing import List

@dataclass
class GeometryMsgs_Vector3(IdlStruct):
    x: float64
    y: float64
    z: float64

@dataclass
class Time(IdlStruct):
    sec: int32
    nanosec: uint32

@dataclass
class Header(IdlStruct):
    stamp: Time
    frame_id: str

@dataclass
class Position(IdlStruct):
    x: float64
    y: float64
    z: float64

@dataclass
class Orientation(IdlStruct):
    x: float64
    y: float64
    z: float64
    w: float64

@dataclass
class Pose(IdlStruct):
    position: Position
    orientation: Orientation

@dataclass
class PoseStamped(IdlStruct):
    header: Header
    pose: Pose

@dataclass
class PoseWithCovariance(IdlStruct):
    pose: Pose
    covariance: List[float64]
    covariance: pycdr2.types.array[float64, 36]

@dataclass
class Twist(IdlStruct):
    linear: GeometryMsgs_Vector3
    angular: GeometryMsgs_Vector3

@dataclass
class TwistWithCovariance(IdlStruct):
    twist: Twist
    covariance: pycdr2.types.array[float64, 36]

@dataclass
class Path(IdlStruct):
    header: Header
    poses: List[PoseStamped]

@dataclass
class MapMetaData(IdlStruct):
    map_load_time: Time
    resolution: float32
    width: uint32
    height: uint32
    origin: Pose

@dataclass
class OccupancyGrid(IdlStruct):
    header: Header
    info: MapMetaData
    data: List[int8]

@dataclass
class SensorMsgs_BatteryState(IdlStruct):
    header: Header
    voltage: float32
    temperature: float32
    current: float32
    charge: float32
    capacity: float32
    design_capacity: float32
    percentage: float32
    power_supply_status: uint8
    power_supply_health: uint8
    power_supply_technology: uint8
    present: bool
    cell_voltage: List[float32]
    cell_temperature: List[float32]
    location: str
    serial_number: str

@dataclass
class NavMsgs_Odometry(IdlStruct):
    header: Header
    child_frame_id: str
    pose: PoseWithCovariance
    twist: TwistWithCovariance

@dataclass
class MotorState(IdlStruct):
    id: uint8
    voltage: float32
    name: str
    speed: int64
    position: int64
    temperature: uint16
    payload: int16
    is_enabled: bool
    is_powered: bool
    is_faulted: bool
    is_connected: bool
    error_code: uint8
    error_message: str

@dataclass
class MotorStates(IdlStruct):
    header: Header
    motor_states: List[MotorState]

@dataclass
class StdMsgs_Bool(IdlStruct):
    data: bool

@dataclass
class StdMsgs_Empty(IdlStruct):
    pass

@dataclass
class SensorMsgs_LaserScan(IdlStruct):
    header: Header
    angle_min: float32
    angle_max: float32
    angle_increment: float32
    time_increment: float32
    scan_time: float32
    range_min: float32
    range_max: float32
    ranges: List[float32]
    intensities: List[float32]

@dataclass
class RclInterfaces_ParameterValue(IdlStruct):
    type: uint8
    bool_value: bool = None
    integer_value: int64 = None
    double_value: float64 = None
    string_value: str = None
    byte_array_value: List[uint8] = None
    boolean_array_value: List[bool] = None
    integer_array_value: List[int64] = None
    double_array_value: List[float64] = None
    string_array_value: List[str] = None
@dataclass
class RclInterfaces_Parameter(IdlStruct):
    name: str
    value: RclInterfaces_ParameterValue
@dataclass
class SetParameters_Request(IdlStruct):
    parameters: List[RclInterfaces_Parameter]

@dataclass
class RclInterfaces_SetParametersResult(IdlStruct):
    successful: bool
    reason: str
@dataclass
class SetParameters_Response(IdlStruct):
    results: List[RclInterfaces_SetParametersResult]

@dataclass
class NavigateThroughPoses_GetResult_Request(IdlStruct):
    goal_id: pycdr2.types.array[pycdr2.types.uint8, 16]


@dataclass
class StdMsgs_MultiArrayDimension(IdlStruct):
    label: str
    size: uint32
    stride: uint32
@dataclass
class StdMsgs_MultiArrayLayout(IdlStruct):
    dim: List[StdMsgs_MultiArrayDimension]
    data_offset: uint32

@dataclass
class StdMsgs_UInt8MultiArray(IdlStruct):
    layout: StdMsgs_MultiArrayLayout
    data: List[uint8]

@dataclass
class CanMsgs_Frame(IdlStruct):
    id: uint16
    data: List[uint8]

@dataclass
class SensorMsgs_PointField(IdlStruct):
    name: str
    offset: uint32
    datatype: uint8
    count: uint32
    
@dataclass
class SensorMsgs_PointCloud2(IdlStruct):
    header: Header
    height: uint32
    width: uint32
    fields: List[SensorMsgs_PointField]
    is_bigendian: bool
    point_step: uint32
    row_step: uint32
    data: List[uint8]
    is_dense: bool


@dataclass
class Nav2Msgs_CollisionMonitorState(IdlStruct):
    action_type: uint8
    polygon_name: str

@dataclass
class Mp3playerSrv_SetVolume_Request(IdlStruct):
    volume: uint8

@dataclass
class Mp3playerSrv_SetVolume_Response(IdlStruct):
    success: bool
    message: str
    actual_volume: uint8

@dataclass
class Nav2Msgs_BehaviorTreeStatusChange(IdlStruct):
    timestamp: Time
    node_name: str
    previous_status: str
    current_status: str

@dataclass
class Nav2Msgs_BehaviorTreeLog(IdlStruct):
    timestamp: Time
    event_log: List[Nav2Msgs_BehaviorTreeStatusChange]


@dataclass
class DiagnosticMsgs_KeyValue(IdlStruct):
    key: str
    value: str

@dataclass
class DiagnosticMsgs_DiagnosticStatus(IdlStruct):
    level: uint8
    name: str
    message: str
    hardware_id: str
    values: List[DiagnosticMsgs_KeyValue]

@dataclass
class DiagnosticMsgs_DiagnosticArray(IdlStruct):
    header: Header
    status: List[DiagnosticMsgs_DiagnosticStatus]

@dataclass
class GeometryMsgs_Transform(IdlStruct):
    translation: GeometryMsgs_Vector3
    rotation: Orientation
@dataclass
class GeometryMsgs_TransformStamped(IdlStruct):
    header: Header
    child_frame_id: str
    transform: GeometryMsgs_Transform
@dataclass
class Tf2Msgs_TfMessage(IdlStruct):
    transforms: List[GeometryMsgs_TransformStamped]