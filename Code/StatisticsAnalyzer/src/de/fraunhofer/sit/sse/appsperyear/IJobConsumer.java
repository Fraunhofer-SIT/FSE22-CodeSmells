package de.fraunhofer.sit.sse.appsperyear;

import de.fraunhofer.sit.sse.vusc.javaclient.api.KnowledgebaseApi;
import de.fraunhofer.sit.sse.vusc.javaclient.models.Job;

/**
 * Consumer interface for handling a particular VUSC job
 * 
 * @author Steven Arzt
 *
 */
@FunctionalInterface
public interface IJobConsumer {

	/**
	 * Accepts the given job for processing
	 * 
	 * @param j                The job
	 * @param knowledgebaseAPI The API for accessing the knowledgebase of the VUSC
	 *                         server
	 */
	public void accept(Job j, KnowledgebaseApi knowledgebaseAPI);

}
