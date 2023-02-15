#ifdef WINDOWS
#include "Solver.h"
#include "Junction.h"
#include "Simulation.h"
#include "Controller_Base.h"

void CSolver::solveVoltages() {
	for (int i = 0; i < sim->getJunctionsCount(); i++) {
		CJunction *ju = sim->getJunction(i);
		if (ju->isCurrentSource() == false) {
			ju->setVoltage(-1);
			ju->setDuty(-1);
		}
		ju->setVisitCount(0);
	}
	for (int i = 0; i < sim->getJunctionsCount(); i++) {
		CJunction *ju = sim->getJunction(i);
		if (ju->hasName("VDD")) {
			floodJunctions(ju, 3.3f, 100.0f);
		}
		else if (ju->hasName("GND")) {
			floodJunctions(ju, 0, 100.0f);
		}
		else if (ju->isCurrentSource()) {
			floodJunctions(ju, ju->getVoltage(), ju->getDuty());
		}
	}
}
// Idea: count steps to VDD/GND and use it to support multiple objects on line?
void CSolver::floodJunctions(CJunction *ju, float voltage, float duty) {
	if (ju == 0)
		return;
	if (ju->getVisitCount() != 0)
		return;
	ju->setVisitCount(1);
	ju->setVoltage(voltage);
	ju->setDuty(duty);
	for (int i = 0; i < ju->getLinksCount(); i++) {
		CJunction *other = ju->getLink(i);
		floodJunctions(other, voltage, duty);
	}
	for (int i = 0; i < ju->getEdgesCount(); i++) {
		CEdge *e = ju->getEdge(i);
		CJunction *o = e->getOther(ju);
		floodJunctions(o, voltage, duty);
	}
	CControllerBase *cntr = ju->findOwnerController_r();
	if (cntr != 0) {
		CJunction *other = cntr->findOtherJunctionIfPassable(ju);
		if (other) {
			floodJunctions(other, voltage, duty);
		}
	}
}

#endif
